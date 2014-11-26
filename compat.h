#ifndef _COMPAT_H_INCLUDED
#	define _COMPAT_H_INCLUDED

#	define _public_ __attribute__((visibility("default")))

#	define sd_event void
#	define sd_event_source void
#	define sd_event_handler_t void *
#	define sd_resolve void
#	define sd_network_monitor void
#	define sd_login_monitor void
#	define sd_bus void
#	define sd_bus_message void
#	define sd_bus_slot void
#	define sd_bus_message_handler_t void *
#	define sd_bus_error void
#	define sd_bus_creds void
#	define sd_bus_track void
#	define sd_bus_track_handler_t void *
#	define sd_bus_object_find_t void *
#	define sd_resolve_res_handler_t void *
#	define sd_resolve_query void
#	define sd_bus_vtable void
#	define sd_bus_node_enumerator_t void *
#	define sd_resolve_getaddrinfo_handler_t void *
#	define sd_event_signal_handler_t void *
#	define sd_resolve_getnameinfo_handler_t void *
#	define sd_event_io_handler_t void *
#	define sd_event_time_handler_t void *
#	define sd_event_child_handler_t void *

/* from src/systemd/sd-id128.h */
typedef union sd_id128 sd_id128_t;

union sd_id128 {
        uint8_t bytes[16];
        uint64_t qwords[2];
};

#endif
