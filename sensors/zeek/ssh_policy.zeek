@load base/protocols/ssh
@load ./policy_common

module MetadataSSH;
export {
    redef enum Notice::Type += { Crypto_Policy_Violation };
    const weak_kex = /diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1/ &redef;
    const weak_cipher = /(^|[ :])none($|[, ])|arcfour|3des|blowfish|cast128|[a-z0-9]+-cbc/ &redef;
    const weak_mac = /hmac-md5|hmac-sha1|umac-64|(^|[ :])none($|[, ])/ &redef;
    const weak_host_key = /(^|[ :])ssh-rsa($|[, ]|-cert-v01@openssh.com)|ssh-dss/ &redef;
    global check_record: function(rec: SSH::Info): set[string];
}
redef record SSH::Info += {
    policy_version: string &log &default=MetadataPolicy::version;
    policy_violations: set[string] &log &default=set();
    mac_effective: string &log &optional;
};
function directional_algorithms(value: string): string_vec
    {
    local parts = split_string(value, /, to client: /);
    if ( |parts| == 2 && /^To server: / in parts[0] )
        return vector(sub(parts[0], /^To server: /, ""), parts[1]);
    return vector(value, value);
    }
function is_aead(cipher: string): bool
    { return /chacha20-poly1305|gcm/ in cipher; }

function check_record(rec: SSH::Info): set[string]
    {
    local violations: set[string] = set();
    if ( rec?$version && rec$version < 2 ) add violations["SSH_VERSION_NOT_ALLOWED"];
    if ( rec?$kex_alg && weak_kex in rec$kex_alg ) add violations["SSH_KEX_WEAK"];
    if ( rec?$cipher_alg && weak_cipher in rec$cipher_alg ) add violations["SSH_CIPHER_WEAK"];
    # Match cipher/MAC directions; AEAD never uses its separately advertised MAC.
    if ( rec?$cipher_alg && rec?$mac_alg )
        {
        local ciphers = directional_algorithms(rec$cipher_alg);
        local macs = directional_algorithms(rec$mac_alg);
        for ( i in ciphers )
            if ( ! is_aead(ciphers[i]) && weak_mac in macs[i] ) add violations["SSH_MAC_WEAK"];
        }
    if ( rec?$host_key_alg && weak_host_key in rec$host_key_alg ) add violations["SSH_HOST_KEY_SIGNATURE_WEAK"];
    return violations;
    }
function banner_token(value: string): string
    {
    local parts = split_string(value, /[ \t\r\n]+/);
    if ( |parts| == 0 || |parts[0]| > 128 || ! ( /^SSH-[0-9.]+-[A-Za-z0-9_.+@-]+$/ == parts[0] ) ) return "unparsed_ssh_banner";
    return parts[0];
    }
hook SSH::log_policy(rec: SSH::Info, id: Log::ID, filter: Log::Filter)
    {
    if ( rec?$client ) rec$client = banner_token(rec$client);
    if ( rec?$server ) rec$server = banner_token(rec$server);
    if ( rec?$cipher_alg && rec?$mac_alg )
        {
        local ciphers = directional_algorithms(rec$cipher_alg);
        local macs = directional_algorithms(rec$mac_alg);
        local to_server = is_aead(ciphers[0]) ? "aead_implicit" : macs[0];
        local to_client = is_aead(ciphers[1]) ? "aead_implicit" : macs[1];
        rec$mac_effective = to_server == to_client ? to_server : cat("To server: ", to_server, ", to client: ", to_client);
        }
    rec$policy_violations = check_record(rec);
    for ( rule in rec$policy_violations )
        {
        local observed = "unknown";
        if ( rule == "SSH_VERSION_NOT_ALLOWED" && rec?$version ) observed = cat(rec$version);
        if ( rule == "SSH_KEX_WEAK" && rec?$kex_alg ) observed = rec$kex_alg;
        if ( rule == "SSH_CIPHER_WEAK" && rec?$cipher_alg ) observed = rec$cipher_alg;
        if ( rule == "SSH_MAC_WEAK" && rec?$mac_alg ) observed = rec$mac_alg;
        if ( rule == "SSH_HOST_KEY_SIGNATURE_WEAK" && rec?$host_key_alg ) observed = rec$host_key_alg;
        MetadataPolicy::emit(rec$uid, rec$id, Crypto_Policy_Violation, rule, observed);
        }
    }
