@load base/protocols/ssl
module TLSExtensions;
export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        uid: string &log;
        metadata_version: string &log &default="tls-extensions-v1";
        client_hello_observed: bool &log &default=F;
        server_hello_observed: bool &log &default=F;
        client_extensions: set[count] &log &default=set();
        server_extensions: set[count] &log &default=set();
        # Extension presence != ECH accepted; GREASE co the co cung extension.
        ech_observed: bool &log &optional;
        client_signature_schemes: vector of count &log &optional;
        server_signature_scheme: count &log &optional;
    };
}
redef record connection += { tls_extensions: Info &optional; };
function ensure(c: connection)
    { if ( ! c?$tls_extensions ) c$tls_extensions=[$ts=c$start_time, $uid=c$uid]; }
event zeek_init() &priority=5
    { Log::create_stream(LOG, [$columns=Info, $path="tls_extensions"]); }
event ssl_extension(c: connection, is_client: bool, code: count, val: string)
    {
    ensure(c);
    # Chi luu code. Tuyet doi khong ghi val (raw extension).
    if ( is_client ) add c$tls_extensions$client_extensions[code];
    else add c$tls_extensions$server_extensions[code];
    }
event ssl_client_hello(c: connection, version: count, record_version: count,
    possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
    {
    ensure(c);
    c$tls_extensions$client_hello_observed=T;
    # Chi ket luan absent khi da thay ClientHello; khong luu random/session_id.
    c$tls_extensions$ech_observed = 65037 in c$tls_extensions$client_extensions;
    }
event ssl_server_hello(c: connection, version: count, record_version: count,
    possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
    { ensure(c); c$tls_extensions$server_hello_observed=T; }
event ssl_extension_signature_algorithm(c: connection, is_client: bool, signature_algorithms: signature_and_hashalgorithm_vec)
    {
    if ( ! is_client ) return;
    ensure(c);
    local codes: vector of count = vector();
    for ( i in signature_algorithms )
        codes[|codes|] = signature_algorithms[i]$HashAlgorithm * 256 + signature_algorithms[i]$SignatureAlgorithm;
    c$tls_extensions$client_signature_schemes=codes;
    }
event ssl_server_signature(c: connection, signature_and_hashalgorithm: SSL::SignatureAndHashAlgorithm, signature: string)
    {
    ensure(c);
    c$tls_extensions$server_signature_scheme = signature_and_hashalgorithm$HashAlgorithm * 256 + signature_and_hashalgorithm$SignatureAlgorithm;
    # Khong ghi signature bytes. TLS1.3 encrypted -> field thieu.
    }
event connection_state_remove(c: connection) &priority=-10
    {
    if ( ! c?$tls_extensions ) return;
    # Chot sau cac extension event, tranh phu thuoc thu tu callback ClientHello.
    if ( c$tls_extensions$client_hello_observed )
        c$tls_extensions$ech_observed = 65037 in c$tls_extensions$client_extensions;
    Log::write(LOG, c$tls_extensions);
    }
