#ifndef HELIOS_CORE_H
#define HELIOS_CORE_H
#include <stddef.h>
#include <stdint.h>
// All pointers are borrowed only for the duration of a call.
int32_t helios_tunnel_start(const char *node_json, const char *shared_container);
int32_t helios_tunnel_push(const uint8_t *bytes, size_t length); // 0 accepted; 1 queue full; -1 invalid/stopped
int32_t helios_tunnel_pop(uint8_t *buffer, size_t capacity); // 0 empty; positive length; -1 stopped
size_t helios_tunnel_snapshot(uint8_t *buffer, size_t capacity); // required JSON length; no NUL
void helios_tunnel_stop(void);
void helios_tunnel_clear_logs(void);
void helios_tunnel_recheck(void);
void helios_tunnel_network_changed(void);
#endif
