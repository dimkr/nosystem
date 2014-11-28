#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <stddef.h>

#include "compat.h"

_public_ int sd_network_get_operational_state(char **state) {
	return -EINVAL;
}

_public_ int sd_network_get_dns(char ***ret) {
	return -EINVAL;
}

_public_ int sd_network_get_ntp(char ***ret) {
	return -EINVAL;
}

_public_ int sd_network_get_domains(char ***ret) {
	return -EINVAL;
}

_public_ int sd_network_link_get_setup_state(int ifindex, char **state) {
	return -EINVAL;
}

_public_ int sd_network_link_get_network_file(int ifindex, char **filename) {
	return -EINVAL;
}

_public_ int sd_network_link_get_operational_state(int ifindex, char **state) {
	return -EINVAL;
}

_public_ int sd_network_link_get_llmnr(int ifindex, char **llmnr) {
	return -EINVAL;
}

_public_ int sd_network_link_get_dns(int ifindex, char ***ret) {
	return -EINVAL;
}

_public_ int sd_network_link_get_ntp(int ifindex, char ***ret) {
	return -EINVAL;
}

_public_ int sd_network_link_get_domains(int ifindex, char ***ret) {
	return -EINVAL;
}

_public_ int sd_network_link_get_wildcard_domain(int ifindex) {
	return -EINVAL;
}

_public_ int sd_network_monitor_new(sd_network_monitor **m, const char *category) {
	return -EINVAL;
}

_public_ sd_network_monitor* sd_network_monitor_unref(sd_network_monitor *m) {
	return NULL;
}

_public_ int sd_network_monitor_flush(sd_network_monitor *m) {
	return -EINVAL;
}

_public_ int sd_network_monitor_get_fd(sd_network_monitor *m) {
	return -EINVAL;
}

_public_ int sd_network_monitor_get_events(sd_network_monitor *m) {
	return -EINVAL;
}

_public_ int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *timeout_usec) {
	return -EINVAL;
}

_public_ const char *sd_utf8_is_valid(const char *s) {
	return NULL;
}

_public_ const char *sd_ascii_is_valid(const char *s) {
	return NULL;
}

_public_ int sd_pid_get_session(pid_t pid, char **session) {
	return -EINVAL;
}

_public_ int sd_pid_get_unit(pid_t pid, char **unit) {
	return -EINVAL;
}

_public_ int sd_pid_get_user_unit(pid_t pid, char **unit) {
	return -EINVAL;
}

_public_ int sd_pid_get_machine_name(pid_t pid, char **name) {
	return -EINVAL;
}

_public_ int sd_pid_get_slice(pid_t pid, char **slice) {
	return -EINVAL;
}

_public_ int sd_pid_get_owner_uid(pid_t pid, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_peer_get_session(int fd, char **session) {
	return -EINVAL;
}

_public_ int sd_peer_get_owner_uid(int fd, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_peer_get_unit(int fd, char **unit) {
	return -EINVAL;
}

_public_ int sd_peer_get_user_unit(int fd, char **unit) {
	return -EINVAL;
}

_public_ int sd_peer_get_machine_name(int fd, char **machine) {
	return -EINVAL;
}

_public_ int sd_peer_get_slice(int fd, char **slice) {
	return -EINVAL;
}

_public_ int sd_uid_get_state(uid_t uid, char**state) {
	return -EINVAL;
}

_public_ int sd_uid_get_display(uid_t uid, char **session) {
	return -EINVAL;
}

_public_ int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat) {
	return -EINVAL;
}

_public_ int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions) {
	return -EINVAL;
}

_public_ int sd_uid_get_seats(uid_t uid, int require_active, char ***seats) {
	return -EINVAL;
}

_public_ int sd_session_is_active(const char *session) {
	return -EINVAL;
}

_public_ int sd_session_is_remote(const char *session) {
	return -EINVAL;
}

_public_ int sd_session_get_state(const char *session, char **state) {
	return -EINVAL;
}

_public_ int sd_session_get_uid(const char *session, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_session_get_seat(const char *session, char **seat) {
	return -EINVAL;
}

_public_ int sd_session_get_tty(const char *session, char **tty) {
	return -EINVAL;
}

_public_ int sd_session_get_vt(const char *session, unsigned *vtnr) {
	return -EINVAL;
}

_public_ int sd_session_get_service(const char *session, char **service) {
	return -EINVAL;
}

_public_ int sd_session_get_type(const char *session, char **type) {
	return -EINVAL;
}

_public_ int sd_session_get_class(const char *session, char **class) {
	return -EINVAL;
}

_public_ int sd_session_get_desktop(const char *session, char **desktop) {
	return -EINVAL;
}

_public_ int sd_session_get_display(const char *session, char **display) {
	return -EINVAL;
}

_public_ int sd_session_get_remote_user(const char *session, char **remote_user) {
	return -EINVAL;
}

_public_ int sd_session_get_remote_host(const char *session, char **remote_host) {
	return -EINVAL;
}

_public_ int sd_seat_get_active(const char *seat, char **session, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_seat_get_sessions(const char *seat, char ***sessions, uid_t **uids, unsigned *n_uids) {
	return -EINVAL;
}

_public_ int sd_seat_can_multi_session(const char *seat) {
	return -EINVAL;
}

_public_ int sd_seat_can_tty(const char *seat) {
	return -EINVAL;
}

_public_ int sd_seat_can_graphical(const char *seat) {
	return -EINVAL;
}

_public_ int sd_get_seats(char ***seats) {
	return -EINVAL;
}

_public_ int sd_get_sessions(char ***sessions) {
	return -EINVAL;
}

_public_ int sd_get_uids(uid_t **users) {
	return -EINVAL;
}

_public_ int sd_get_machine_names(char ***machines) {
	return -EINVAL;
}

_public_ int sd_machine_get_class(const char *machine, char **class) {
	return -EINVAL;
}

_public_ int sd_machine_get_ifindices(const char *machine, int **ifindices) {
	return -EINVAL;
}

_public_ int sd_login_monitor_new(const char *category, sd_login_monitor **m) {
	return -EINVAL;
}

_public_ sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m) {
	return NULL;
}

_public_ int sd_login_monitor_flush(sd_login_monitor *m) {
	return -EINVAL;
}

_public_ int sd_login_monitor_get_fd(sd_login_monitor *m) {
	return -EINVAL;
}

_public_ int sd_login_monitor_get_events(sd_login_monitor *m) {
	return -EINVAL;
}

_public_ int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *timeout_usec) {
	return -EINVAL;
}

_public_ int sd_bus_new(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_set_address(sd_bus *bus, const char *address) {
	return -EINVAL;
}

_public_ int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd) {
	return -EINVAL;
}

_public_ int sd_bus_set_exec(sd_bus *bus, const char *path, char *const argv[]) {
	return -EINVAL;
}

_public_ int sd_bus_set_bus_client(sd_bus *bus, int b) {
	return -EINVAL;
}

_public_ int sd_bus_set_monitor(sd_bus *bus, int b) {
	return -EINVAL;
}

_public_ int sd_bus_negotiate_fds(sd_bus *bus, int b) {
	return -EINVAL;
}

_public_ int sd_bus_negotiate_timestamp(sd_bus *bus, int b) {
	return -EINVAL;
}

_public_ int sd_bus_negotiate_creds(sd_bus *bus, uint64_t mask) {
	return -EINVAL;
}

_public_ int sd_bus_set_server(sd_bus *bus, int b, sd_id128_t server_id) {
	return -EINVAL;
}

_public_ int sd_bus_set_anonymous(sd_bus *bus, int b) {
	return -EINVAL;
}

_public_ int sd_bus_set_trusted(sd_bus *bus, int b) {
	return -EINVAL;
}

_public_ int sd_bus_set_name(sd_bus *bus, const char *name) {
	return -EINVAL;
}

_public_ int sd_bus_start(sd_bus *bus) {
	return -EINVAL;
}

_public_ int sd_bus_open(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_open_system(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_open_user(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_open_system_remote(sd_bus **ret, const char *host) {
	return -EINVAL;
}

_public_ int sd_bus_open_system_container(sd_bus **ret, const char *machine) {
	return -EINVAL;
}

_public_ void sd_bus_close(sd_bus *bus) {
}

_public_ sd_bus *sd_bus_ref(sd_bus *bus) {
	return NULL;
}

_public_ sd_bus *sd_bus_unref(sd_bus *bus) {
	return NULL;
}

_public_ int sd_bus_is_open(sd_bus *bus) {
	return -EINVAL;
}

_public_ int sd_bus_can_send(sd_bus *bus, char type) {
	return -EINVAL;
}

_public_ int sd_bus_get_server_id(sd_bus *bus, sd_id128_t *server_id) {
	return -EINVAL;
}

_public_ int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *cookie) {
	return -EINVAL;
}

_public_ int sd_bus_send_to(sd_bus *bus, sd_bus_message *m, const char *destination, uint64_t *cookie) {
	return -EINVAL;
}

_public_ int sd_bus_call_async(sd_bus *bus, sd_bus_slot **slot, sd_bus_message *m, sd_bus_message_handler_t callback, void *userdata, uint64_t usec) {
	return -EINVAL;
}

_public_ int sd_bus_call(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *ret_error, sd_bus_message **reply) {
	return -EINVAL;
}

_public_ int sd_bus_get_fd(sd_bus *bus) {
	return -EINVAL;
}

_public_ int sd_bus_get_events(sd_bus *bus) {
	return -EINVAL;
}

_public_ int sd_bus_get_timeout(sd_bus *bus, uint64_t *timeout_usec) {
	return -EINVAL;
}

_public_ int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
	return -EINVAL;
}

_public_ int sd_bus_process_priority(sd_bus *bus, int64_t priority, sd_bus_message **ret) {
	return -EINVAL;
}

_public_ int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {
	return -EINVAL;
}

_public_ int sd_bus_flush(sd_bus *bus) {
	return -EINVAL;
}

_public_ int sd_bus_add_filter(sd_bus *bus, sd_bus_slot **slot, sd_bus_message_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_add_match(sd_bus *bus, sd_bus_slot **slot, const char *match, sd_bus_message_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_attach_event(sd_bus *bus, sd_event *event, int priority) {
	return -EINVAL;
}

_public_ int sd_bus_detach_event(sd_bus *bus) {
	return -EINVAL;
}

_public_ sd_event* sd_bus_get_event(sd_bus *bus) {
	return NULL;
}

_public_ sd_bus_message* sd_bus_get_current_message(sd_bus *bus) {
	return NULL;
}

_public_ sd_bus_slot* sd_bus_get_current_slot(sd_bus *bus) {
	return NULL;
}

_public_ sd_bus_message_handler_t sd_bus_get_current_handler(sd_bus *bus) {
	return NULL;
}

_public_ void* sd_bus_get_current_userdata(sd_bus *bus) {
	return NULL;
}

_public_ int sd_bus_default_system(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_default_user(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_default(sd_bus **ret) {
	return -EINVAL;
}

_public_ int sd_bus_get_tid(sd_bus *b, pid_t *tid) {
	return -EINVAL;
}

_public_ int sd_bus_path_encode(const char *prefix, const char *external_id, char **ret_path) {
	return -EINVAL;
}

_public_ int sd_bus_path_decode(const char *path, const char *prefix, char **external_id) {
	return -EINVAL;
}

_public_ int sd_bus_try_close(sd_bus *bus) {
	return -EINVAL;
}

_public_ int sd_bus_get_name(sd_bus *bus, const char **name) {
	return -EINVAL;
}

_public_ int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
	return -EINVAL;
}

_public_ int sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags) {
	return -EINVAL;
}

_public_ int sd_bus_release_name(sd_bus *bus, const char *name) {
	return -EINVAL;
}

_public_ int sd_bus_list_names(sd_bus *bus, char ***acquired, char ***activatable) {
	return -EINVAL;
}

_public_ int sd_bus_get_name_creds(sd_bus *bus, const char *name, uint64_t mask, sd_bus_creds **creds) {
	return -EINVAL;
}

_public_ int sd_bus_get_owner_creds(sd_bus *bus, uint64_t mask, sd_bus_creds **ret) {
	return -EINVAL;
}

_public_ int sd_bus_get_name_machine_id(sd_bus *bus, const char *name, sd_id128_t *machine) {
	return -EINVAL;
}

_public_ void sd_bus_error_free(sd_bus_error *e) {
}

_public_ int sd_bus_error_set(sd_bus_error *e, const char *name, const char *message) {
	return -EINVAL;
}

_public_ int sd_bus_error_setf(sd_bus_error *e, const char *name, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_bus_error_copy(sd_bus_error *dest, const sd_bus_error *e) {
	return -EINVAL;
}

_public_ int sd_bus_error_set_const(sd_bus_error *e, const char *name, const char *message) {
	return -EINVAL;
}

_public_ int sd_bus_error_is_set(const sd_bus_error *e) {
	return -EINVAL;
}

_public_ int sd_bus_error_has_name(const sd_bus_error *e, const char *name) {
	return -EINVAL;
}

_public_ int sd_bus_error_get_errno(const sd_bus_error* e) {
	return -EINVAL;
}

_public_ int sd_bus_error_set_errno(sd_bus_error *e, int error) {
	return -EINVAL;
}

_public_ int sd_bus_error_set_errnof(sd_bus_error *e, int error, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_bus_emit_signal(sd_bus *bus, const char *path, const char *interface, const char *member, const char *types, ...) {
	return -EINVAL;
}

_public_ int sd_bus_call_method(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *types, ...) {
	return -EINVAL;
}

_public_ int sd_bus_reply_method_return(sd_bus_message *call, const char *types, ...) {
	return -EINVAL;
}

_public_ int sd_bus_reply_method_error(sd_bus_message *call, const sd_bus_error *e) {
	return -EINVAL;
}

_public_ int sd_bus_reply_method_errorf(sd_bus_message *call, const char *name, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_bus_reply_method_errno(sd_bus_message *call, int error, const sd_bus_error *e) {
	return -EINVAL;
}

_public_ int sd_bus_reply_method_errnof(sd_bus_message *call, int error, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_bus_get_property(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *type) {
	return -EINVAL;
}

_public_ int sd_bus_get_property_trivial(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, char type, void *ret_ptr) {
	return -EINVAL;
}

_public_ int sd_bus_get_property_string(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_get_property_strv(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, char ***ret) {
	return -EINVAL;
}

_public_ int sd_bus_set_property(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, const char *ret_type, ...) {
	return -EINVAL;
}

_public_ int sd_bus_query_sender_creds(sd_bus_message *call, uint64_t mask, sd_bus_creds **creds) {
	return -EINVAL;
}

_public_ int sd_bus_query_sender_privilege(sd_bus_message *call, int capability) {
	return -EINVAL;
}

_public_ int sd_bus_track_new(sd_bus *bus, sd_bus_track **track, sd_bus_track_handler_t handler, void *userdata) {
	return -EINVAL;
}

_public_ sd_bus_track* sd_bus_track_ref(sd_bus_track *track) {
	return NULL;
}

_public_ sd_bus_track* sd_bus_track_unref(sd_bus_track *track) {
	return NULL;
}

_public_ int sd_bus_track_add_name(sd_bus_track *track, const char *name) {
	return -EINVAL;
}

_public_ int sd_bus_track_remove_name(sd_bus_track *track, const char *name) {
	return -EINVAL;
}

_public_ unsigned sd_bus_track_count(sd_bus_track *track) {
	return -EINVAL;
}

_public_ const char* sd_bus_track_contains(sd_bus_track *track, const char *name) {
	return NULL;
}

_public_ const char* sd_bus_track_first(sd_bus_track *track) {
	return NULL;
}

_public_ const char* sd_bus_track_next(sd_bus_track *track) {
	return NULL;
}

_public_ int sd_bus_track_add_sender(sd_bus_track *track, sd_bus_message *m) {
	return -EINVAL;
}

_public_ int sd_bus_track_remove_sender(sd_bus_track *track, sd_bus_message *m) {
	return -EINVAL;
}

_public_ sd_bus* sd_bus_track_get_bus(sd_bus_track *track) {
	return NULL;
}

_public_ void *sd_bus_track_get_userdata(sd_bus_track *track) {
	return NULL;
}

_public_ void *sd_bus_track_set_userdata(sd_bus_track *track, void *userdata) {
	return NULL;
}

_public_ sd_bus_slot* sd_bus_slot_ref(sd_bus_slot *slot) {
	return NULL;
}

_public_ sd_bus_slot* sd_bus_slot_unref(sd_bus_slot *slot) {
	return NULL;
}

_public_ sd_bus* sd_bus_slot_get_bus(sd_bus_slot *slot) {
	return NULL;
}

_public_ void *sd_bus_slot_get_userdata(sd_bus_slot *slot) {
	return NULL;
}

_public_ void *sd_bus_slot_set_userdata(sd_bus_slot *slot, void *userdata) {
	return NULL;
}

_public_ sd_bus_message *sd_bus_slot_get_current_message(sd_bus_slot *slot) {
	return NULL;
}

_public_ sd_bus_message_handler_t sd_bus_slot_get_current_handler(sd_bus_slot *slot) {
	return NULL;
}

_public_ void* sd_bus_slot_get_current_userdata(sd_bus_slot *slot) {
	return NULL;
}

_public_ int sd_bus_add_object(sd_bus *bus, sd_bus_slot **slot, const char *path, sd_bus_message_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_add_fallback(sd_bus *bus, sd_bus_slot **slot, const char *prefix, sd_bus_message_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_add_object_vtable(sd_bus *bus, sd_bus_slot **slot, const char *path, const char *interface, const sd_bus_vtable *vtable, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_add_fallback_vtable(sd_bus *bus, sd_bus_slot **slot, const char *prefix, const char *interface, const sd_bus_vtable *vtable, sd_bus_object_find_t find, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_add_node_enumerator(sd_bus *bus, sd_bus_slot **slot, const char *path, sd_bus_node_enumerator_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_bus_emit_properties_changed_strv(sd_bus *bus, const char *path, const char *interface, char **names) {
	return -EINVAL;
}

_public_ int sd_bus_emit_properties_changed(sd_bus *bus, const char *path, const char *interface, const char *name, ...) {
	return -EINVAL;
}

_public_ int sd_bus_emit_interfaces_added_strv(sd_bus *bus, const char *path, char **interfaces) {
	return -EINVAL;
}

_public_ int sd_bus_emit_interfaces_added(sd_bus *bus, const char *path, const char *interface, ...) {
	return -EINVAL;
}

_public_ int sd_bus_emit_interfaces_removed_strv(sd_bus *bus, const char *path, char **interfaces) {
	return -EINVAL;
}

_public_ int sd_bus_emit_interfaces_removed(sd_bus *bus, const char *path, const char *interface, ...) {
	return -EINVAL;
}

_public_ int sd_bus_add_object_manager(sd_bus *bus, sd_bus_slot **slot, const char *path) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_signal(sd_bus *bus, sd_bus_message **m, const char *path, const char *interface, const char *member) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_method_call(sd_bus *bus, sd_bus_message **m, const char *destination, const char *path, const char *interface, const char *member) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_method_return(sd_bus_message *call, sd_bus_message **m) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_method_error(sd_bus_message *call, sd_bus_message **m, const sd_bus_error *e) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_method_errorf(sd_bus_message *call, sd_bus_message **m, const char *name, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_method_errno(sd_bus_message *call, sd_bus_message **m, int error, const sd_bus_error *e) {
	return -EINVAL;
}

_public_ int sd_bus_message_new_method_errnof(sd_bus_message *call, sd_bus_message **m, int error, const char *format, ...) {
	return -EINVAL;
}

_public_ sd_bus_message* sd_bus_message_ref(sd_bus_message *m) {
	return NULL;
}

_public_ sd_bus_message* sd_bus_message_unref(sd_bus_message *m) {
	return NULL;
}

_public_ int sd_bus_message_get_type(sd_bus_message *m, uint8_t *type) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_cookie(sd_bus_message *m, uint64_t *cookie) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_reply_cookie(sd_bus_message *m, uint64_t *cookie) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_expect_reply(sd_bus_message *m) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_auto_start(sd_bus_message *m) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_allow_interactive_authorization(sd_bus_message *m) {
	return -EINVAL;
}

_public_ const char *sd_bus_message_get_path(sd_bus_message *m) {
	return NULL;
}

_public_ const char *sd_bus_message_get_interface(sd_bus_message *m) {
	return NULL;
}

_public_ const char *sd_bus_message_get_member(sd_bus_message *m) {
	return NULL;
}

_public_ const char *sd_bus_message_get_destination(sd_bus_message *m) {
	return NULL;
}

_public_ const char *sd_bus_message_get_sender(sd_bus_message *m) {
	return NULL;
}

_public_ const sd_bus_error *sd_bus_message_get_error(sd_bus_message *m) {
	return NULL;
}

_public_ int sd_bus_message_get_monotonic_usec(sd_bus_message *m, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_realtime_usec(sd_bus_message *m, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_seqnum(sd_bus_message *m, uint64_t *seqnum) {
	return -EINVAL;
}

_public_ sd_bus_creds *sd_bus_message_get_creds(sd_bus_message *m) {
	return NULL;
}

_public_ int sd_bus_message_is_signal(sd_bus_message *m, const char *interface, const char *member) {
	return -EINVAL;
}

_public_ int sd_bus_message_is_method_call(sd_bus_message *m, const char *interface, const char *member) {
	return -EINVAL;
}

_public_ int sd_bus_message_is_method_error(sd_bus_message *m, const char *name) {
	return -EINVAL;
}

_public_ int sd_bus_message_set_expect_reply(sd_bus_message *m, int b) {
	return -EINVAL;
}

_public_ int sd_bus_message_set_auto_start(sd_bus_message *m, int b) {
	return -EINVAL;
}

_public_ int sd_bus_message_set_allow_interactive_authorization(sd_bus_message *m, int b) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *p) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_string_space(sd_bus_message *m, size_t size, char **s) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_string_iovec(sd_bus_message *m, const struct iovec *iov, unsigned n) {
	return -EINVAL;
}

_public_ int sd_bus_message_open_container(sd_bus_message *m, char type, const char *contents) {
	return -EINVAL;
}

_public_ int sd_bus_message_close_container(sd_bus_message *m) {
	return -EINVAL;
}

_public_ int sd_bus_message_append(sd_bus_message *m, const char *types, ...) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_array_space(sd_bus_message *m, char type, size_t size, void **ptr) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_array(sd_bus_message *m, char type, const void *ptr, size_t size) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_array_iovec(sd_bus_message *m, char type, const struct iovec *iov, unsigned n) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_array_memfd(sd_bus_message *m, char type, int memfd) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_string_memfd(sd_bus_message *m, int memfd) {
	return -EINVAL;
}

_public_ int sd_bus_message_append_strv(sd_bus_message *m, char **l) {
	return -EINVAL;
}

_public_ int sd_bus_message_at_end(sd_bus_message *m, int complete) {
	return -EINVAL;
}

_public_ int sd_bus_message_read_basic(sd_bus_message *m, char type, void *p) {
	return -EINVAL;
}

_public_ int sd_bus_message_enter_container(sd_bus_message *m, char type, const char *contents) {
	return -EINVAL;
}

_public_ int sd_bus_message_exit_container(sd_bus_message *m) {
	return -EINVAL;
}

_public_ int sd_bus_message_peek_type(sd_bus_message *m, char *type, const char **contents) {
	return -EINVAL;
}

_public_ int sd_bus_message_rewind(sd_bus_message *m, int complete) {
	return -EINVAL;
}

_public_ int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
	return -EINVAL;
}

_public_ int sd_bus_message_skip(sd_bus_message *m, const char *types) {
	return -EINVAL;
}

_public_ int sd_bus_message_read_array(sd_bus_message *m, char type, const void **ptr, size_t *size) {
	return -EINVAL;
}

_public_ int sd_bus_message_set_destination(sd_bus_message *m, const char *destination) {
	return -EINVAL;
}

_public_ int sd_bus_message_read_strv(sd_bus_message *m, char ***l) {
	return -EINVAL;
}

_public_ int sd_bus_message_get_errno(sd_bus_message *m) {
	return -EINVAL;
}

_public_ const char* sd_bus_message_get_signature(sd_bus_message *m, int complete) {
	return NULL;
}

_public_ int sd_bus_message_copy(sd_bus_message *m, sd_bus_message *source, int all) {
	return -EINVAL;
}

_public_ int sd_bus_message_verify_type(sd_bus_message *m, char type, const char *contents) {
	return -EINVAL;
}

_public_ sd_bus *sd_bus_message_get_bus(sd_bus_message *m) {
	return NULL;
}

_public_ int sd_bus_message_get_priority(sd_bus_message *m, int64_t *priority) {
	return -EINVAL;
}

_public_ int sd_bus_message_set_priority(sd_bus_message *m, int64_t priority) {
	return -EINVAL;
}

_public_ sd_bus_creds *sd_bus_creds_ref(sd_bus_creds *c) {
	return NULL;
}

_public_ sd_bus_creds *sd_bus_creds_unref(sd_bus_creds *c) {
	return NULL;
}

_public_ uint64_t sd_bus_creds_get_mask(const sd_bus_creds *c) {
	return -EINVAL;
}

_public_ int sd_bus_creds_new_from_pid(sd_bus_creds **ret, pid_t pid, uint64_t mask) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_uid(sd_bus_creds *c, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_gid(sd_bus_creds *c, gid_t *gid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_pid(sd_bus_creds *c, pid_t *pid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_tid(sd_bus_creds *c, pid_t *tid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_pid_starttime(sd_bus_creds *c, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_selinux_context(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_comm(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_tid_comm(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_exe(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_cgroup(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_unit(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_user_unit(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_slice(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_session(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_owner_uid(sd_bus_creds *c, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_cmdline(sd_bus_creds *c, char ***cmdline) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_audit_session_id(sd_bus_creds *c, uint32_t *sessionid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_audit_login_uid(sd_bus_creds *c, uid_t *uid) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_unique_name(sd_bus_creds *c, const char **unique_name) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_well_known_names(sd_bus_creds *c, char ***well_known_names) {
	return -EINVAL;
}

_public_ int sd_bus_creds_get_connection_name(sd_bus_creds *c, const char **ret) {
	return -EINVAL;
}

_public_ int sd_bus_creds_has_effective_cap(sd_bus_creds *c, int capability) {
	return -EINVAL;
}

_public_ int sd_bus_creds_has_permitted_cap(sd_bus_creds *c, int capability) {
	return -EINVAL;
}

_public_ int sd_bus_creds_has_inheritable_cap(sd_bus_creds *c, int capability) {
	return -EINVAL;
}

_public_ int sd_bus_creds_has_bounding_cap(sd_bus_creds *c, int capability) {
	return -EINVAL;
}

_public_ int sd_listen_fds(int unset_environment) {
	return -EINVAL;
}

_public_ int sd_is_fifo(int fd, const char *path) {
	return -EINVAL;
}

_public_ int sd_is_special(int fd, const char *path) {
	return -EINVAL;
}

_public_ int sd_is_socket(int fd, int family, int type, int listening) {
	return -EINVAL;
}

_public_ int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port) {
	return -EINVAL;
}

_public_ int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) {
	return -EINVAL;
}

_public_ int sd_is_mq(int fd, const char *path) {
	return -EINVAL;
}

_public_ int sd_pid_notify(pid_t pid, int unset_environment, const char *state) {
	return -EINVAL;
}

_public_ int sd_notify(int unset_environment, const char *state) {
	return -EINVAL;
}

_public_ int sd_pid_notifyf(pid_t pid, int unset_environment, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_notifyf(int unset_environment, const char *format, ...) {
	return -EINVAL;
}

_public_ int sd_booted(void) {
	return -EINVAL;
}

_public_ int sd_watchdog_enabled(int unset_environment, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_resolve_new(sd_resolve **ret) {
	return -EINVAL;
}

_public_ int sd_resolve_default(sd_resolve **ret) {
	return -EINVAL;
}

_public_ int sd_resolve_get_tid(sd_resolve *resolve, pid_t *tid) {
	return -EINVAL;
}

_public_ sd_resolve* sd_resolve_ref(sd_resolve *resolve) {
	return NULL;
}

_public_ sd_resolve* sd_resolve_unref(sd_resolve *resolve) {
	return NULL;
}

_public_ int sd_resolve_get_fd(sd_resolve *resolve) {
	return -EINVAL;
}

_public_ int sd_resolve_get_events(sd_resolve *resolve) {
	return -EINVAL;
}

_public_ int sd_resolve_get_timeout(sd_resolve *resolve, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_resolve_process(sd_resolve *resolve) {
	return -EINVAL;
}

_public_ int sd_resolve_wait(sd_resolve *resolve, uint64_t timeout_usec) {
	return -EINVAL;
}

_public_ int sd_resolve_getaddrinfo(sd_resolve *resolve, sd_resolve_query **q, const char *node, const char *service, const struct addrinfo *hints, sd_resolve_getaddrinfo_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_resolve_getnameinfo(sd_resolve *resolve, sd_resolve_query **q, const struct sockaddr *sa, socklen_t salen, int flags, uint64_t get, sd_resolve_getnameinfo_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_resolve_res_query(sd_resolve *resolve, sd_resolve_query** q, const char *dname, int class, int type, sd_resolve_res_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_resolve_res_search(sd_resolve *resolve, sd_resolve_query** q, const char *dname, int class, int type, sd_resolve_res_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ sd_resolve_query* sd_resolve_query_ref(sd_resolve_query *q) {
	return NULL;
}

_public_ sd_resolve_query* sd_resolve_query_unref(sd_resolve_query* q) {
	return NULL;
}

_public_ int sd_resolve_query_is_done(sd_resolve_query *q) {
	return -EINVAL;
}

_public_ void* sd_resolve_query_set_userdata(sd_resolve_query *q, void *userdata) {
	return NULL;
}

_public_ void* sd_resolve_query_get_userdata(sd_resolve_query *q) {
	return NULL;
}

_public_ sd_resolve *sd_resolve_query_get_resolve(sd_resolve_query *q) {
	return NULL;
}

_public_ int sd_resolve_attach_event(sd_resolve *resolve, sd_event *event, int priority) {
	return -EINVAL;
}

_public_ int sd_resolve_detach_event(sd_resolve *resolve) {
	return -EINVAL;
}

_public_ sd_event *sd_resolve_get_event(sd_resolve *resolve) {
	return NULL;
}

_public_ char *sd_id128_to_string(sd_id128_t id, char s[33]) {
	return NULL;
}

_public_ int sd_id128_from_string(const char s[], sd_id128_t *ret) {
	return -EINVAL;
}

_public_ int sd_id128_get_machine(sd_id128_t *ret) {
	return -EINVAL;
}

_public_ int sd_id128_get_boot(sd_id128_t *ret) {
	return -EINVAL;
}

_public_ int sd_id128_randomize(sd_id128_t *ret) {
	return -EINVAL;
}

_public_ int sd_path_home(uint64_t type, const char *suffix, char **path) {
	return -EINVAL;
}

_public_ int sd_path_search(uint64_t type, const char *suffix, char ***paths) {
	return -EINVAL;
}

_public_ int sd_event_new(sd_event** ret) {
	return -EINVAL;
}

_public_ sd_event* sd_event_ref(sd_event *e) {
	return NULL;
}

_public_ sd_event* sd_event_unref(sd_event *e) {
	return NULL;
}

_public_ int sd_event_add_io(sd_event *e, sd_event_source **s, int fd, uint32_t events, sd_event_io_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_event_add_time(sd_event *e, sd_event_source **s, clockid_t clock, uint64_t usec, uint64_t accuracy, sd_event_time_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_event_add_signal(sd_event *e, sd_event_source **s, int sig, sd_event_signal_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_event_add_child(sd_event *e, sd_event_source **s, pid_t pid, int options, sd_event_child_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_event_add_defer(sd_event *e, sd_event_source **s, sd_event_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_event_add_post(sd_event *e, sd_event_source **s, sd_event_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ int sd_event_add_exit(sd_event *e, sd_event_source **s, sd_event_handler_t callback, void *userdata) {
	return -EINVAL;
}

_public_ sd_event_source* sd_event_source_ref(sd_event_source *s) {
	return NULL;
}

_public_ sd_event_source* sd_event_source_unref(sd_event_source *s) {
	return NULL;
}

_public_ int sd_event_source_set_name(sd_event_source *s, const char *name) {
	return -EINVAL;
}

_public_ int sd_event_source_get_name(sd_event_source *s, const char **name) {
	return -EINVAL;
}

_public_ sd_event *sd_event_source_get_event(sd_event_source *s) {
	return NULL;
}

_public_ int sd_event_source_get_pending(sd_event_source *s) {
	return -EINVAL;
}

_public_ int sd_event_source_get_io_fd(sd_event_source *s) {
	return -EINVAL;
}

_public_ int sd_event_source_set_io_fd(sd_event_source *s, int fd) {
	return -EINVAL;
}

_public_ int sd_event_source_get_io_events(sd_event_source *s, uint32_t* events) {
	return -EINVAL;
}

_public_ int sd_event_source_set_io_events(sd_event_source *s, uint32_t events) {
	return -EINVAL;
}

_public_ int sd_event_source_get_io_revents(sd_event_source *s, uint32_t* revents) {
	return -EINVAL;
}

_public_ int sd_event_source_get_signal(sd_event_source *s) {
	return -EINVAL;
}

_public_ int sd_event_source_get_priority(sd_event_source *s, int64_t *priority) {
	return -EINVAL;
}

_public_ int sd_event_source_set_priority(sd_event_source *s, int64_t priority) {
	return -EINVAL;
}

_public_ int sd_event_source_get_enabled(sd_event_source *s, int *m) {
	return -EINVAL;
}

_public_ int sd_event_source_set_enabled(sd_event_source *s, int m) {
	return -EINVAL;
}

_public_ int sd_event_source_get_time(sd_event_source *s, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_event_source_set_time(sd_event_source *s, uint64_t usec) {
	return -EINVAL;
}

_public_ int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec) {
	return -EINVAL;
}

_public_ int sd_event_source_get_time_clock(sd_event_source *s, clockid_t *clock) {
	return -EINVAL;
}

_public_ int sd_event_source_get_child_pid(sd_event_source *s, pid_t *pid) {
	return -EINVAL;
}

_public_ int sd_event_source_set_prepare(sd_event_source *s, sd_event_handler_t callback) {
	return -EINVAL;
}

_public_ void* sd_event_source_get_userdata(sd_event_source *s) {
	return NULL;
}

_public_ void *sd_event_source_set_userdata(sd_event_source *s, void *userdata) {
	return NULL;
}

_public_ int sd_event_prepare(sd_event *e) {
	return -EINVAL;
}

_public_ int sd_event_wait(sd_event *e, uint64_t timeout) {
	return -EINVAL;
}

_public_ int sd_event_dispatch(sd_event *e) {
	return -EINVAL;
}

_public_ int sd_event_run(sd_event *e, uint64_t timeout) {
	return -EINVAL;
}

_public_ int sd_event_loop(sd_event *e) {
	return -EINVAL;
}

_public_ int sd_event_get_fd(sd_event *e) {
	return -EINVAL;
}

_public_ int sd_event_get_state(sd_event *e) {
	return -EINVAL;
}

_public_ int sd_event_get_exit_code(sd_event *e, int *code) {
	return -EINVAL;
}

_public_ int sd_event_exit(sd_event *e, int code) {
	return -EINVAL;
}

_public_ int sd_event_now(sd_event *e, clockid_t clock, uint64_t *usec) {
	return -EINVAL;
}

_public_ int sd_event_default(sd_event **ret) {
	return -EINVAL;
}

_public_ int sd_event_get_tid(sd_event *e, pid_t *tid) {
	return -EINVAL;
}

_public_ int sd_event_set_watchdog(sd_event *e, int b) {
	return -EINVAL;
}

_public_ int sd_event_get_watchdog(sd_event *e) {
	return -EINVAL;
}

