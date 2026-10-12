function expect(value: bool, message: string)
    { if ( ! value ) Reporter::fatal(message); }

event zeek_init() &priority=-30
    {
    local id: conn_id = [$orig_h=192.0.2.1, $orig_p=12345/tcp, $resp_h=192.0.2.2, $resp_p=443/tcp, $proto=6];
    local tls: SSL::Info = [$ts=current_time(), $uid="testTLS", $id=id];
    expect(|MetadataTLS::check_record(tls)| == 0, "missing TLS metadata must not mean weak");
    tls$version = "TLSv13";
    tls$cipher = "TLS_AES_128_GCM_SHA256";
    expect(|MetadataTLS::check_record(tls)| == 0, "modern TLS");
    tls$version = "TLSv10";
    tls$cipher = "TLS_RSA_WITH_AES_128_CBC_SHA";
    tls$cert_key_type = "rsa";
    tls$cert_key_bits = 1024;
    tls$cert_sig_alg = "sha1WithRSAEncryption";
    tls$cert_validity_status = "expired";
    tls$cert_trust_status = "untrusted";
    tls$sni_matches_cert = F;
    expect(|MetadataTLS::check_record(tls)| == 7, "seven independent TLS weaknesses");
    tls$cert_key_type = "ec";
    tls$cert_key_bits = 224;
    expect("TLS_EC_KEY_TOO_SMALL" in MetadataTLS::check_record(tls), "EC key threshold");
    tls$cert_key_type = "dsa";
    expect("TLS_DSA_KEY_NOT_ALLOWED" in MetadataTLS::check_record(tls), "DSA certificate");
    tls$cert_key_type = "rsa-pss";
    tls$cert_key_bits = 1024;
    expect("TLS_RSA_KEY_TOO_SMALL" in MetadataTLS::check_record(tls), "RSA-PSS key threshold");
    tls$cert_validity_status = "not_yet_valid";
    expect("TLS_CERT_NOT_YET_VALID" in MetadataTLS::check_record(tls), "future validity");
    tls$server_name = "PRIVATE_PAYLOAD_MARKER";
    tls$subject = "PRIVATE_PAYLOAD_MARKER";
    Log::write(SSL::LOG, tls);
    local ssh: SSH::Info = [$ts=current_time(), $uid="testSSH", $id=id];
    expect(|MetadataSSH::check_record(ssh)| == 0, "missing SSH metadata");
    ssh$version = 2;
    ssh$kex_alg = "curve25519-sha256";
    ssh$host_key_alg = "ssh-ed25519";
    ssh$cipher_alg = "chacha20-poly1305@openssh.com";
    ssh$mac_alg = "hmac-sha1";
    expect(|MetadataSSH::check_record(ssh)| == 0, "AEAD advertised MAC must not cause false positive");
    ssh$cipher_alg = "To server: chacha20-poly1305@openssh.com, to client: aes128-ctr";
    ssh$mac_alg = "To server: hmac-sha1, to client: hmac-sha2-256";
    expect(|MetadataSSH::check_record(ssh)| == 0, "mixed directions must not use AEAD advertised MAC");
    ssh$mac_alg = "To server: hmac-sha2-256, to client: hmac-sha1";
    expect("SSH_MAC_WEAK" in MetadataSSH::check_record(ssh), "mixed directions weak effective MAC");
    ssh$mac_alg = "hmac-sha1";
    ssh$cipher_alg = "aes128-ctr";
    expect("SSH_MAC_WEAK" in MetadataSSH::check_record(ssh), "non-AEAD weak MAC");
    ssh$version = 1;
    ssh$kex_alg = "diffie-hellman-group1-sha1";
    ssh$cipher_alg = "aes128-cbc";
    ssh$host_key_alg = "ssh-rsa";
    expect(|MetadataSSH::check_record(ssh)| == 5, "five independent SSH weaknesses");
    ssh$client = "SSH-2.0-OpenSSH_9.9 PRIVATE_PAYLOAD_MARKER";
    ssh$server = "SSH-2.0-OpenSSH_9.9 PRIVATE_PAYLOAD_MARKER";
    ssh$hasshAlgorithms = "PRIVATE_PAYLOAD_MARKER";
    Log::write(SSH::LOG, ssh);
    local weird: Weird::Info = [$ts=current_time(), $uid="testWeird", $id=id,
        $name="metadata_test", $addl="PRIVATE_PAYLOAD_MARKER"];
    Log::write(Weird::LOG, weird);
    local conn: Conn::Info = [$ts=current_time(), $uid="testConn", $id=id, $proto=tcp];
    Log::write(Conn::LOG, conn);
    print "PASS: missing data, modern crypto, weak crypto, AEAD MAC and privacy fixtures";
    }
