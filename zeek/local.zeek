# Moi dong log la mot JSON object, de doc bang PowerShell/Python sau nay.
@load policy/tuning/json-logs

# Chi ghi metadata ket noi va handshake TLS/SSH.
const allowed_logs: set[Log::ID] = {
    Conn::LOG, SSL::LOG, X509::LOG, SSH::LOG
};

hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    if ( id !in allowed_logs )
        break;
    }

# Tao file log theo tung phut cho cac lan thu nghiem ngan.
redef Log::default_rotation_interval = 1min;
# Khong nap file extraction; khong cau hinh PCAP dumping hay TLS decryption.
