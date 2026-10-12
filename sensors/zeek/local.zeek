@load base/protocols/conn
@load base/misc/version
@load base/protocols/ssl
@load base/files/x509
@load base/protocols/ssh
@load base/frameworks/notice/weird
@load base/protocols/conn/thresholds
@load policy/tuning/json-logs
# Configure the pinned JA4 package BEFORE its conditional loads.
@load packages/ja4/config
redef FINGERPRINT::JA4H_enabled = F;
redef FINGERPRINT::JA4D_enabled = F;
redef FINGERPRINT::JA4L_enabled = F;
redef FINGERPRINT::JA4T_enabled = F;
redef FINGERPRINT::JA4TS_enabled = F;
redef FINGERPRINT::JA4X_enabled = F;
redef FINGERPRINT::JA4_raw = F;
redef FINGERPRINT::JA4S_raw = F;
@load packages/ja4
@load packages/ja3/ja3
@load packages/ja3/ja3s
@load packages/hassh
module SSH;
redef log_raw_hassh_algorithms = F;
redef log_key_algorithm = F;
module GLOBAL;
@load ./tls_policy
@load ./ssh_policy
@load ./metadata_fields

# Runs with zeek -b: no default site/L7 scripts or TLS decryption.
redef Analyzer::disable_all = T;
redef Analyzer::requested_analyzers += { Analyzer::ANALYZER_SSL, Analyzer::ANALYZER_SSH, Analyzer::ANALYZER_CONNSIZE };
redef SSH::ports += { 2222/tcp };
redef Site::local_nets = { 172.30.10.0/24, 172.30.20.0/24, 172.30.30.0/24 };
redef Log::default_rotation_interval = 1min;
