module MetadataFields;

redef record Conn::Info += {
    # Last JA4SSH packet window, calculated by pinned package before conn removal.
    ja4ssh: string &log &optional;
};
event connection_state_remove(c: connection) &priority=-1
    {
    if ( c?$conn && c?$fp && c$fp?$ja4ssh && c$fp$ja4ssh$is_ssh )
        c$conn$ja4ssh = c$fp$ja4ssh$ja4ssh;
    }

export {
    const columns: table[Log::ID] of set[string] = {
        [Conn::LOG] = set("ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service",
            "duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes",
            "history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","ip_proto","ja4ssh"),
        [SSL::LOG] = set("ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","version","cipher",
            "curve","resumed","established","last_alert","ssl_history","sni_matches_cert","cert_chain_fps",
            "client_cert_chain_fps","validation_status","ja3","ja3s","ja4","ja4s","policy_version",
            "policy_violations","handshake_status","certificate_visible","cert_fingerprint","cert_spki_sha256",
            "cert_key_type","cert_key_bits","cert_sig_alg","cert_not_valid_before","cert_not_valid_after",
            "cert_validity_status","cert_chain_len","cert_trust_status","issuer_name_sha256"),
        [X509::LOG] = set("ts","fingerprint","certificate.version","certificate.not_valid_before",
            "certificate.not_valid_after","certificate.key_alg","certificate.sig_alg","certificate.key_type",
            "certificate.key_length","certificate.curve","host_cert","client_cert","spki_sha256",
            "issuer_name_sha256","subject_name_sha256","issuer_class","san_dns_count","san_ip_count"),
        [SSH::LOG] = set("ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","version",
            "auth_success","auth_attempts","direction","client","server","cipher_alg","mac_alg",
            "compression_alg","kex_alg","host_key_alg","host_key_fingerprint","hasshVersion","hassh",
            "hasshServer","policy_version","policy_violations","mac_effective"),
        # Native descriptions can include attacker-controlled values; omit them.
        [Notice::LOG] = set("ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","note","actions",
            "rule_id","policy_version","observed_metadata"),
        [Weird::LOG] = set("ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","name","notice","source")
    } &redef;
}
event zeek_init() &priority=-20
    {
    for ( id in columns )
        {
        Log::remove_filter(id, "default");
        Log::add_filter(id, [$name="metadata_only", $include=columns[id]]);
        }
    }
hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    if ( id !in columns ) break;
    }
