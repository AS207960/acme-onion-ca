alter table issuing_certs
    alter column ocsp_responder_url type text[] using array[ocsp_responder_url];