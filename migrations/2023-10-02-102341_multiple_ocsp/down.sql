alter table issuing_certs
    alter column ocsp_responder_url type text using coalesce(ocsp_responder_url[1], '');