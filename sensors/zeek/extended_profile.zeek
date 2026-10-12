# Opt-in: entrypoint chi load file nay khi ZEEK_EXTENDED_METADATA=true.
# Thu tu: local.zeek -> extended_profile.zeek -> zeek_init.
@load ./packet_metadata
@load ./tls_extensions
redef MetadataFields::columns += {
    [PacketMetadata::LOG] = set("ts","uid","metadata_version","sequence_limit",
        "orig_observed_packets","resp_observed_packets","orig_iat_count","resp_iat_count",
        "orig_iat_mean","orig_iat_std","resp_iat_mean","resp_iat_std","unordered_timestamps",
        "pkt_size_vector","pkt_direction_vector","sequence_truncated","tcp_flags_orig","tcp_flags_resp"),
    [TLSExtensions::LOG] = set("ts","uid","metadata_version","client_hello_observed",
        "server_hello_observed","client_extensions","server_extensions","ech_observed",
        "client_signature_schemes","server_signature_scheme")
};
