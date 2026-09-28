// SPDX-License-Identifier: AGPL-3.0-or-later

// The Endpoint Security client of wardend on macOS. One client per process; the handler block
// runs on ES's own queue, copies the exec into a flat wc_exec_t and hands it to Go (goESExec),
// which answers through wc_es_respond, at once or after a hold. See esgate_darwin.go for the flow
// and spikes/es-exec-gate/es_gate_spike.c for the experiment this grew from.
//
// Built only on a Mac (cgo, EndpointSecurity.framework, libbsm). Checked here by eye: there is no
// clang on the Linux build host and gcc has no block syntax.

#include "esgate_darwin.h"
#include "_cgo_export.h"

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <mach/mach_time.h>
#include <stdlib.h>
#include <string.h>

// WC_PACK_MAX bounds one packed argv or env (Linux: 4096 strings of 128 KiB; a big environment
// is a few hundred KiB). Over it the buffer is marked truncated and Go fails closed on argv.
#define WC_PACK_MAX (8u << 20)

// The macOS 27 additions, by name: a build against an older SDK has no prototypes for them.
typedef es_new_client_result_t (*wc_new_descendants_fn)(es_client_t **client, es_handler_block_t handler);
typedef es_return_t (*wc_set_deadline_miss_fn)(es_client_t *client, int mode);
typedef es_return_t (*wc_set_deadline_min_fn)(es_client_t *client, const es_event_type_t *events, uint32_t count, uint32_t ms);
typedef es_return_t (*wc_get_deadline_min_fn)(es_client_t *client, es_event_type_t event, uint32_t *ms);

// The value of ES_DEADLINE_MISS_MODE_FAIL_CLOSED comes from the SDK only: a build against an SDK
// that predates it (26 and older) reports no deadline mode, even on a macOS 27 host where the
// symbol resolves. Guessing the value could select FAIL_OPEN. Build with the macOS 27 SDK.
// The test is the SDK version, not #ifdef ES_DEADLINE_MISS_MODE_FAIL_CLOSED: that name is an
// enumerator of es_deadline_miss_mode_t (a typedef enum, "c:@EA@es_deadline_miss_mode_t" in
// Apple's documentation), which the preprocessor never sees, so #ifdef was false on every SDK and
// fail-closed could not be selected even on the 27 SDK.
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 270000
#define WC_HAVE_DEADLINE_MODE 1
#else
#define WC_HAVE_DEADLINE_MODE 0
#endif

static es_client_t *g_client;
static mach_timebase_info_data_t g_tb;

static void *wc_sym(const char *name) { return dlsym(RTLD_DEFAULT, name); }

int wc_es_has_descendants(void) { return wc_sym("es_new_descendants_client") != NULL; }
int wc_es_has_deadline_mode(void) { return WC_HAVE_DEADLINE_MODE && wc_sym("es_set_deadline_miss_mode") != NULL; }

static wc_str_t wc_tok(es_string_token_t t) {
    wc_str_t s = {t.data, t.length};
    return s;
}

// wc_deadline_ms: what is left of the message deadline, in ms (0 when it has passed).
static int64_t wc_deadline_ms(const es_message_t *msg) {
    uint64_t now = mach_absolute_time();
    if (msg->deadline <= now) return 0;
    uint64_t ticks = msg->deadline - now;
    // ticks * numer / denom is ns; split to avoid an overflow on a far deadline
    uint64_t ns = (ticks / g_tb.denom) * g_tb.numer + ((ticks % g_tb.denom) * g_tb.numer) / g_tb.denom;
    return (int64_t)(ns / 1000000u);
}

// wc_pack copies argv (env: 0) or envp (env: 1) of the exec into one malloc'd buffer of
// NUL-separated strings. *count is how many strings are in it, *truncated whether packing stopped
// before the end (WC_PACK_MAX, or out of memory).
static char *wc_pack(const es_event_exec_t *ex, int env, uint32_t *count, size_t *len, int *truncated) {
    uint32_t n = env ? es_exec_env_count(ex) : es_exec_arg_count(ex);
    size_t cap = 4096, used = 0;
    char *buf = malloc(cap);
    *count = 0;
    *len = 0;
    *truncated = 0;
    if (!buf) {
        *truncated = 1;
        return NULL;
    }
    uint32_t i;
    for (i = 0; i < n; i++) {
        es_string_token_t t = env ? es_exec_env(ex, i) : es_exec_arg(ex, i);
        if (used + t.length + 1 > WC_PACK_MAX) {
            *truncated = 1;
            break;
        }
        while (used + t.length + 1 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                *truncated = 1;
                return NULL;
            }
            buf = nb;
        }
        if (t.length) memcpy(buf + used, t.data, t.length);
        used += t.length;
        buf[used++] = 0;
    }
    *count = i;
    *len = used;
    return buf;
}

// wc_handle runs on ES's queue for every subscribed message. AUTH_EXEC is retained and owned by
// Go until wc_es_respond; the notifications are read and forgotten.
static void wc_handle(es_client_t *c, const es_message_t *msg) {
    (void)c;
    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC: {
        es_retain_message(msg);
        const es_event_exec_t *ex = &msg->event.exec;
        const es_process_t *p = msg->process;
        wc_exec_t x;
        memset(&x, 0, sizeof x);
        x.pid = audit_token_to_pid(p->audit_token);
        x.ppid = p->ppid;
        x.pidversion = (int32_t)audit_token_to_pidversion(p->audit_token);
        x.euid = audit_token_to_euid(p->audit_token);
        x.egid = audit_token_to_egid(p->audit_token);
        x.start_sec = p->start_time.tv_sec;
        x.start_usec = p->start_time.tv_usec;
        x.caller_exe = wc_tok(p->executable->path);
        x.target_exe = wc_tok(ex->target->executable->path);
        if (ex->script) x.script = wc_tok(ex->script->path);
        if (ex->cwd) x.cwd = wc_tok(ex->cwd->path);
        const struct stat *st = &ex->target->executable->stat;
        x.target_dev = (uint64_t)(uint32_t)st->st_dev;
        x.target_ino = (uint64_t)st->st_ino;
        x.target_uid = st->st_uid;
        x.target_mode = st->st_mode;
        x.deadline_ms = wc_deadline_ms(msg);
        x.is_platform_binary = p->is_platform_binary ? 1 : 0;
        char *argv = wc_pack(ex, 0, &x.argc, &x.argv_len, &x.argv_truncated);
        char *env = wc_pack(ex, 1, &x.envc, &x.env_len, &x.env_truncated);
        x.argv = argv;
        x.env = env;
        goESExec(&x, (void *)msg);
        free(argv);
        free(env);
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_FORK:
        goESFork(audit_token_to_pid(msg->process->audit_token), audit_token_to_pid(msg->event.fork.child->audit_token));
        break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        goESExit(audit_token_to_pid(msg->process->audit_token));
        break;
    default:
        break;
    }
}

int wc_es_open(int descendants, int fail_closed, int track_tree, uint32_t min_deadline_ms, uint32_t *floor_ms, const char **err) {
    *err = "";
    *floor_ms = 0;
    if (g_client) {
        *err = "an Endpoint Security client is already open in this process";
        return WC_ES_ERR_BUSY;
    }
    mach_timebase_info(&g_tb);
    es_handler_block_t handler = ^(es_client_t *c, const es_message_t *msg) { wc_handle(c, msg); };
    es_client_t *client = NULL;
    es_new_client_result_t r;
    if (descendants) {
        wc_new_descendants_fn f = (wc_new_descendants_fn)wc_sym("es_new_descendants_client");
        if (!f) {
            *err = "es_new_descendants_client is not available on this macOS";
            return WC_ES_ERR_NO_DESCENDANTS;
        }
        r = f(&client, handler);
    } else {
        r = es_new_client(&client, handler);
    }
    switch (r) {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
        break;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        *err = "es_new_client: not entitled (com.apple.developer.endpoint-security.client; on a development machine: SIP off and boot-args amfi_get_out_of_my_way=1)";
        return WC_ES_ERR_NOT_ENTITLED;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        *err = "es_new_client: not privileged (wardend must run as root)";
        return WC_ES_ERR_NOT_PRIVILEGED;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        *err = "es_new_client: not permitted (grant wardend Full Disk Access in System Settings > Privacy & Security)";
        return WC_ES_ERR_NOT_PERMITTED;
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
        *err = "es_new_client: too many Endpoint Security clients on this system";
        return WC_ES_ERR_OTHER;
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
        *err = "es_new_client: invalid argument";
        return WC_ES_ERR_OTHER;
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
    default:
        *err = "es_new_client: internal error";
        return WC_ES_ERR_OTHER;
    }
    if (fail_closed) {
#if WC_HAVE_DEADLINE_MODE
        wc_set_deadline_miss_fn f = (wc_set_deadline_miss_fn)wc_sym("es_set_deadline_miss_mode");
        if (!f) {
            es_delete_client(client);
            *err = "es_set_deadline_miss_mode is not available on this macOS";
            return WC_ES_ERR_NO_DEADLINE_MODE;
        }
        if (f(client, ES_DEADLINE_MISS_MODE_FAIL_CLOSED) != ES_RETURN_SUCCESS) {
            es_delete_client(client);
            *err = "es_set_deadline_miss_mode(FAIL_CLOSED) failed";
            return WC_ES_ERR_OTHER;
        }
#else
        es_delete_client(client);
        *err = "this wardend was built against an SDK without ES_DEADLINE_MISS_MODE_FAIL_CLOSED (macOS 27 SDK needed)";
        return WC_ES_ERR_NO_DEADLINE_MODE;
#endif
    }
    if (descendants && min_deadline_ms > 0) {
        // The ticket TTL fits inside the kernel's deadline: a descendants client may raise the
        // floor above the system default (the header: "will effectively extend deadlines beyond
        // the system default"), and the command then waits for the whole TTL as on Linux.
        wc_set_deadline_min_fn setmin = (wc_set_deadline_min_fn)wc_sym("es_set_deadline_min_milliseconds");
        wc_get_deadline_min_fn getmin = (wc_get_deadline_min_fn)wc_sym("es_get_deadline_min_milliseconds");
        es_event_type_t ev = ES_EVENT_TYPE_AUTH_EXEC;
        if (!setmin || setmin(client, &ev, 1, min_deadline_ms) != ES_RETURN_SUCCESS) {
            es_delete_client(client);
            *err = "es_set_deadline_min_milliseconds(AUTH_EXEC) failed: the ticket TTL cannot be fitted into the kernel's deadline";
            return WC_ES_ERR_OTHER;
        }
        uint32_t got = 0;
        if (getmin && getmin(client, ev, &got) == ES_RETURN_SUCCESS) *floor_ms = got;
        else *floor_ms = min_deadline_ms;
    }
    es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT};
    if (es_subscribe(client, events, track_tree ? 3 : 1) != ES_RETURN_SUCCESS) {
        es_delete_client(client);
        *err = "es_subscribe failed";
        return WC_ES_ERR_SUBSCRIBE;
    }
    g_client = client;
    return WC_ES_OK;
}

int wc_es_respond(void *m, int allow) {
    const es_message_t *msg = (const es_message_t *)m;
    if (!g_client) return -1;
    // cache: never. A cached ALLOW would let the next exec of the same file pass unseen.
    es_respond_result_t r = es_respond_auth_result(g_client, msg, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
    es_release_message(msg);
    return (int)r;
}

void wc_es_close(void) {
    es_client_t *c = g_client;
    if (!c) return;
    g_client = NULL;
    es_unsubscribe_all(c);
    es_delete_client(c);
}
