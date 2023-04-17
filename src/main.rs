#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate diesel_derive_enum;

mod schema;
mod models;
mod ca;

pub mod cert_order {
    tonic::include_proto!("cert_order");
}

#[derive(Deserialize)]
struct Config {
    listen: std::net::SocketAddr,
    database_url: String,
    validator_url: String,
}

type DBPool = diesel_async::pooled_connection::mobc::Pool<diesel_async::AsyncPgConnection>;
type DBConn = mobc::Connection<diesel_async::pooled_connection::AsyncDieselConnectionManager<diesel_async::AsyncPgConnection>>;

pub const MIGRATIONS: diesel_migrations::EmbeddedMigrations = diesel_migrations::embed_migrations!("migrations");

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
    let ca = ca::CA {
        db: db_pool,
        validator: mobc::Pool::new(ca::ValidatorManager {
            endpoint: validator_endpoint
                .concurrency_limit(8)
                .user_agent("ACME for Onions CA").unwrap()
                .tcp_keepalive(Some(std::time::Duration::from_secs(5)))
                .connect_timeout(std::time::Duration::from_secs(5)),
        })
    };
    let server_future = tonic::transport::Server::builder()
        .add_service(cert_order::ca_server::CaServer::new(ca))
        .serve(config.listen);

    info!("Listening for requests on {}", config.listen);
    rt.block_on(server_future).expect("failed to run the future on runtime");
}
