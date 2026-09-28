# Requires FoxIO JA4 compiled plugin (zkg install zeek/foxio/ja4).
# Uses only JA4 client fingerprint; no server response and no TLS decryption.
@load packages
module VEIL;

global check_fingerprint: event(id: conn_id, attempt: count);
event new_connection(c: connection) {
    if (observed_destination(c$id$resp_h))
        schedule 1sec { check_fingerprint(c$id, 0) };
}
event check_fingerprint(id: conn_id, attempt: count) {
    if (!connection_exists(id)) return;
    local c = lookup_connection(id);
    if (c?$fp && c$fp?$client_hello && c$fp$client_hello?$version) {
        local fp = JA4::calculate_ja4(c, FINGERPRINT::delimiter);
        if (fp$ja4 != "")
            Log::write(LOG, [$ts=network_time(),$kind="tls",$uid=c$uid,
                $src=c$id$orig_h,$dst=c$id$resp_h,$ja4=fp$ja4]);
    }
    else if (attempt < 5)
        schedule 1sec { check_fingerprint(id, attempt+1) };
}
