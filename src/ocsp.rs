use chrono::prelude::*;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

#[tonic::async_trait]
impl crate::cert_order::ocsp_server::Ocsp for crate::ca::CA {
    async fn check_cert(
        &self, request: tonic::Request<crate::cert_order::CheckCertRequest>
    ) -> Result<tonic::Response<crate::cert_order::CheckCertResponse>, tonic::Status> {
        let request = request.into_inner();
        let now = Utc::now();

        let serial = if request.serial_number[0] == 0 {
            &request.serial_number[1..]
        } else {
            &request.serial_number
        };

        debug!("OCSP request for serial number {:?}", request.serial_number);
        let cert_id = match uuid::Uuid::from_slice(serial) {
            Ok(id) => id,
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::CheckCertResponse {
                status: crate::cert_order::CertStatus::CertUnissued.into(),
                this_update: Some(now.into()),
                next_update: Some((now + chrono::Duration::days(365)).into()),
                ..Default::default()
            }))
        };

        let mut conn = self.get_db_conn().await?;
        let certificate: crate::models::Certificate = match crate::ca::handle_db_result(crate::schema::certificate::table
            .find(cert_id).get_result(&mut conn).await.optional())? {
            Some(c) => c,
            None => return Ok(tonic::Response::new(crate::cert_order::CheckCertResponse {
                status: crate::cert_order::CertStatus::CertUnissued.into(),
                this_update: Some(now.into()),
                next_update: Some((now + chrono::Duration::days(7)).into()),
                ..Default::default()
            }))
        };

        if certificate.revoked {
            return Ok(tonic::Response::new(crate::cert_order::CheckCertResponse {
                status: crate::cert_order::CertStatus::CertRevoked.into(),
                revocation_reason: certificate.revocation_reason.unwrap_or_default() as i32,
                this_update: Some(now.into()),
                next_update: Some((now + chrono::Duration::days(365)).into()),
                revocation_timestamp: certificate.revocation_timestamp.map(|t| t.into()),
                invalidity_date: certificate.invalidity_date.map(|t| t.into()),
                ..Default::default()
            }))
        }

        Ok(tonic::Response::new(crate::cert_order::CheckCertResponse {
            status: crate::cert_order::CertStatus::CertGood.into(),
            this_update: Some(now.into()),
            next_update: Some((now + chrono::Duration::days(3)).into()),
            ..Default::default()
        }))
    }
}