#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate diesel_derive_enum;

mod schema;
mod models;
mod ca;
mod sct;
mod ocsp;

pub mod cert_order {
    tonic::include_proto!("cert_order");
}

#[derive(Deserialize, Debug)]
struct Config {
    listen: std::net::SocketAddr,
    database_url: String,
    validator_url: String,
    issuing_cert_id: uuid::Uuid,
    ct_logs: Vec<CTLog>,
    signing_key: SigningKeyConf,
}

#[derive(Deserialize, Debug)]
struct SigningKeyConf {
    key_id: String,
    pin: String,
}

#[derive(Deserialize, Debug)]
struct CTLog {
    #[serde(deserialize_with = "de_url")]
    url: reqwest::Url,
    expiry_range: Option<CTLogExpiryRange>
}

#[derive(Deserialize, Debug)]
struct CTLogExpiryRange {
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
}

type DBPool = diesel_async::pooled_connection::mobc::Pool<diesel_async::AsyncPgConnection>;
type DBConn = mobc::Connection<diesel_async::pooled_connection::AsyncDieselConnectionManager<diesel_async::AsyncPgConnection>>;

pub const MIGRATIONS: diesel_migrations::EmbeddedMigrations = diesel_migrations::embed_migrations!("migrations");

pub struct P11Engine(*mut openssl_sys::ENGINE);

impl Drop for P11Engine {
    fn drop(&mut self) {
        trace!("Dropping PKCS#11 engine");
        unsafe {
            cvt(openssl_sys::ENGINE_free(self.0)).unwrap();
        }
    }
}

unsafe impl Send for P11Engine {}

impl std::ops::Deref for P11Engine {
    type Target = *mut openssl_sys::ENGINE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for P11Engine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn de_url<'de, D: serde::de::Deserializer<'de>>(d: D) -> Result<reqwest::Url, D::Error> {
    use std::str::FromStr;
    use serde::Deserialize;

    let str = String::deserialize(d)?;
    Ok(reqwest::Url::from_str(&str).map_err(serde::de::Error::custom)?)
}

fn main() {
    use diesel_migrations::MigrationHarness;
    use diesel::Connection;

    pretty_env_logger::init();

    info!("Loading config");
    let env = config::Environment::with_prefix("ACME_ONION_CA")
        .prefix_separator("_")
        .separator("_")
        .keep_prefix(false);
    let file = config::File::new("config.toml", config::FileFormat::Toml)
        .required(false);
    let config = match config::Config::builder()
        .add_source(env)
        .add_source(file)
        .build() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get config: {}", e);
            std::process::exit(1);
        }
    };

    let config: Config = match config.try_deserialize() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {}", e);
            std::process::exit(1);
        }
    };

    let validator_endpoint = match tonic::transport::Endpoint::try_from(config.validator_url) {
        Ok(v) => v,
        Err(e) => {
            error!("Invalid validator URL: {}", e);
            std::process::exit(1);
        }
    };

    info!("Setting up HSM");
    let engine_id = std::ffi::CString::new("pkcs11").unwrap();
    let engine_pin_ctrl = std::ffi::CString::new("PIN").unwrap();
    let engine_pin = std::ffi::CString::new(config.signing_key.pin).unwrap();

    let pkcs11_engine = match (|| -> Result<_, openssl::error::ErrorStack> { unsafe {
        openssl_sys::ENGINE_load_builtin_engines();
        let engine = P11Engine(cvt_p(openssl_sys::ENGINE_by_id(engine_id.as_ptr()))?);
        cvt(openssl_sys::ENGINE_init(*engine))?;
        cvt(openssl_sys::ENGINE_ctrl_cmd_string(
            *engine, engine_pin_ctrl.as_ptr(), engine_pin.as_ptr(), 1,
        ))?;
        Ok(engine)
    }})() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to setup PKCS#11 engine: {}", e);
            std::process::exit(1);
        }
    };

    let engine_key_id = std::ffi::CString::new(config.signing_key.key_id).unwrap();
    let private_key = match (|| -> Result<_, openssl::error::ErrorStack> { unsafe {
        use foreign_types_shared::ForeignType;

        trace!("Loading OpenSSL UI");
        let ui = cvt_p(openssl_sys::UI_OpenSSL())?;
        trace!("Loading private key");
        let priv_key = cvt_p(openssl_sys::ENGINE_load_private_key(
            *pkcs11_engine, engine_key_id.as_ptr(), ui, std::ptr::null_mut(),
        ))?;
        Ok(openssl::pkey::PKey::<openssl::pkey::Private>::from_ptr(priv_key))
    }})() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to load key from HSM: {}", e);
            std::process::exit(1);
        }
    };

    info!("Setting up runtime");
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to setup Tokio runtime: {}", e);
            std::process::exit(1);
        }
    };

    info!("Running migrations");
    let mut conn = match diesel::pg::PgConnection::establish(&config.database_url)  {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get database connection: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = conn.run_pending_migrations(MIGRATIONS) {
        error!("Failed to run migrations: {}", e);
        std::process::exit(1);
    }

    let db_config = diesel_async::pooled_connection::AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(config.database_url);
    let db_pool = DBPool::new(db_config);

    info!("Starting server");
    let http_client = reqwest::Client::new();

    let ca = ca::CA {
        db: db_pool,
        validator: mobc::Pool::new(ca::ValidatorManager {
            endpoint: validator_endpoint
                .concurrency_limit(8)
                .user_agent("ACME for Onions CA").unwrap()
                .tcp_keepalive(Some(std::time::Duration::from_secs(5)))
                .connect_timeout(std::time::Duration::from_secs(5)),
        }),
        issuing_cert_id: config.issuing_cert_id,
        ct_logs: config.ct_logs.into(),
        http_client: http_client.into(),
        signing_key: private_key.into(),
    };
    let server_future = tonic::transport::Server::builder()
        .add_service(cert_order::ocsp_server::OcspServer::new(ca.clone()))
        .add_service(cert_order::ca_server::CaServer::new(ca))
        .serve(config.listen);

    info!("Listening for requests on {}", config.listen);
    rt.block_on(server_future).expect("failed to run the future on runtime");
}

fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}