// The Rust core (crates/aegis-mobile, ffi.rs) for the iOS app and its
// packet tunnel. Every function returns a JSON object as a string:
// {"ok": true, ...} or {"ok": false, "error": "..."}. Release each result
// with aegis_free. Functions marked "blocks" do network or shutdown work:
// call them off the main thread.
#ifndef AEGIS_CORE_H
#define AEGIS_CORE_H

#include <stdint.h>

/// Join another server with an invitation (aegis1:...) and select it. Blocks.
char *aegis_enroll(const char *dir, const char *code);
/// {"servers": [{id, name, server, certificate_expires_at}], "selected": id}
char *aegis_servers(const char *dir);
/// The server the next connection uses.
char *aegis_select(const char *dir, const char *id);
/// Remove a server and its identity. Blocks.
char *aegis_forget(const char *dir, const char *id);
/// How the packet tunnel sets up its interface: addresses, routes, DNS, MTU.
char *aegis_vpn_config(void);
/// Connect on this process's packet tunnel interface (the extension).
char *aegis_start_tunnel(const char *dir);
/// Disconnect. Blocks until stopped.
char *aegis_stop(void);
/// Connection state and counters.
char *aegis_status(void);
/// Release a string returned by any function above.
void aegis_free(char *s);

#endif
