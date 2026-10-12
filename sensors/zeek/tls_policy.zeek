@load base/protocols/ssl
@load base/files/x509
@load base/protocols/ssl/mozilla-ca-list
@load policy/protocols/ssl/validate-certs
@load ./policy_common

module MetadataTLS;
export {
    redef enum Notice::Type += { Crypto_Policy_Violation, Certificate_Policy_Violation };
    const allowed_versions = set("TLSv12", "TLSv13") &redef;
    const allowed_ciphers = set(
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    ) &redef;
    const min_rsa_bits: count = 2048 &redef;
    const min_ec_bits: count = 256 &redef;
    # Empty by default. Explicit leaf pins may trust a controlled lab certificate.
    # Pins never bypass expiry, hostname, key-size or signature checks.
    const trusted_leaf_fingerprints: set[string] = {} &redef;
    global check_record: function(rec: SSL::Info): set[string];
}
redef record SSL::Info += {
    policy_version: string &log &default=MetadataPolicy::version;
    policy_violations: set[string] &log &default=set();
    handshake_status: string &log &optional;
    certificate_visible: bool &log &default=F;
    cert_fingerprint: string &log &optional;
    cert_spki_sha256: string &log &optional;
    cert_key_type: string &log &optional;
    cert_key_bits: count &log &optional;
    cert_sig_alg: string &log &optional;
    cert_not_valid_before: time &log &optional;
    cert_not_valid_after: time &log &optional;
    cert_validity_status: string &log &optional;
    cert_chain_len: count &log &optional;
    cert_trust_status: string &log &optional;
    issuer_name_sha256: string &log &optional;
};
redef record X509::Info += {
    spki_sha256: string &log &optional;
    issuer_name_sha256: string &log &optional;
    subject_name_sha256: string &log &optional;
    issuer_class: string &log &optional;
    san_dns_count: count &log &default=0;
    san_ip_count: count &log &default=0;
};

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=-5
    {
    if ( ! f$info?$x509 ) return;
    f$info$x509$spki_sha256 = bytestring_to_hexstr(x509_spki_hash(cert_ref, 4));
    f$info$x509$issuer_name_sha256 = bytestring_to_hexstr(x509_issuer_name_hash(cert_ref, 4));
    f$info$x509$subject_name_sha256 = bytestring_to_hexstr(x509_subject_name_hash(cert_ref, 4));
    f$info$x509$issuer_class = cert$issuer == cert$subject ? "self_issued" : "ca_issued";
    }
event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName) &priority=-5
    {
    if ( ! f$info?$x509 ) return;
    if ( ext?$dns ) f$info$x509$san_dns_count = |ext$dns|;
    if ( ext?$ip ) f$info$x509$san_ip_count = |ext$ip|;
    }

hook SSL::ssl_finishing(c: connection) &priority=-10
    {
    if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 || ! c$ssl$cert_chain[0]?$x509 ) return;
    local x = c$ssl$cert_chain[0]$x509;
    local cert = x$certificate;
    c$ssl$certificate_visible = T;
    c$ssl$cert_fingerprint = x$fingerprint;
    c$ssl$cert_chain_len = |c$ssl$cert_chain|;
    c$ssl$cert_sig_alg = cert$sig_alg;
    c$ssl$cert_not_valid_before = cert$not_valid_before;
    c$ssl$cert_not_valid_after = cert$not_valid_after;
    if ( cert?$key_type ) c$ssl$cert_key_type = cert$key_type;
    if ( cert?$key_length ) c$ssl$cert_key_bits = cert$key_length;
    if ( x?$spki_sha256 ) c$ssl$cert_spki_sha256 = x$spki_sha256;
    if ( x?$issuer_name_sha256 ) c$ssl$issuer_name_sha256 = x$issuer_name_sha256;
    c$ssl$cert_validity_status = network_time() < cert$not_valid_before ? "not_yet_valid" :
                               network_time() > cert$not_valid_after ? "expired" : "valid";
    c$ssl$cert_trust_status = x$fingerprint in trusted_leaf_fingerprints ? "pinned_leaf" :
                            c$ssl?$validation_status && c$ssl$validation_status == "ok" ? "valid_chain" : "untrusted";
    }

function check_record(rec: SSL::Info): set[string]
    {
    local violations: set[string] = set();
    if ( rec?$version && rec$version !in allowed_versions ) add violations["TLS_VERSION_NOT_ALLOWED"];
    if ( rec?$cipher && rec$cipher !in allowed_ciphers ) add violations["TLS_CIPHER_NOT_ALLOWED"];
    if ( rec?$cert_key_type && rec?$cert_key_bits )
        {
        local key_type = to_lower(rec$cert_key_type);
        if ( /rsa/ in key_type && rec$cert_key_bits < min_rsa_bits ) add violations["TLS_RSA_KEY_TOO_SMALL"];
        if ( key_type == "ec" && rec$cert_key_bits < min_ec_bits ) add violations["TLS_EC_KEY_TOO_SMALL"];
        if ( key_type == "dsa" ) add violations["TLS_DSA_KEY_NOT_ALLOWED"];
        }
    if ( rec?$cert_sig_alg && /md5|sha1/ in to_lower(rec$cert_sig_alg) ) add violations["TLS_CERT_SIGNATURE_WEAK"];
    if ( rec?$cert_validity_status && rec$cert_validity_status == "expired" ) add violations["TLS_CERT_EXPIRED"];
    if ( rec?$cert_validity_status && rec$cert_validity_status == "not_yet_valid" ) add violations["TLS_CERT_NOT_YET_VALID"];
    if ( rec?$sni_matches_cert && ! rec$sni_matches_cert ) add violations["TLS_CERT_HOSTNAME_MISMATCH"];
    if ( rec?$cert_trust_status && rec$cert_trust_status == "untrusted" ) add violations["TLS_CERT_UNTRUSTED"];
    return violations;
    }

hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter)
    {
    rec$handshake_status = rec$established ? "established" : rec?$last_alert ? "alerted" : "not_established_or_incomplete";
    rec$policy_violations = check_record(rec);
    for ( rule in rec$policy_violations )
        {
        local cert_rule = /^TLS_CERT|^TLS_RSA|^TLS_EC|^TLS_DSA/ in rule;
        local observed = rec?$cipher ? rec$cipher : "unknown";
        if ( rule == "TLS_VERSION_NOT_ALLOWED" && rec?$version ) observed = rec$version;
        if ( /^TLS_RSA|^TLS_EC|^TLS_DSA/ in rule && rec?$cert_key_bits ) observed = cat("key_bits:", rec$cert_key_bits);
        if ( rule == "TLS_CERT_SIGNATURE_WEAK" && rec?$cert_sig_alg ) observed = rec$cert_sig_alg;
        if ( /^TLS_CERT_(EXPIRED|NOT_YET_VALID)/ in rule && rec?$cert_validity_status ) observed = rec$cert_validity_status;
        if ( rule == "TLS_CERT_UNTRUSTED" && rec?$cert_trust_status ) observed = rec$cert_trust_status;
        if ( rule == "TLS_CERT_HOSTNAME_MISMATCH" ) observed = "hostname_mismatch";
        MetadataPolicy::emit(rec$uid, rec$id,
            cert_rule ? Certificate_Policy_Violation : Crypto_Policy_Violation, rule, observed);
        }
    }
