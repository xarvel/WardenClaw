/* SPDX-License-Identifier: AGPL-3.0-or-later */

/* The Endpoint Security client of wardend on macOS (esgate_darwin.c), as Go sees it
 * (esgate_darwin.go). Everything about es_message_t stays in the .c file: Go gets a flat
 * wc_exec_t per AUTH_EXEC and an opaque message handle to answer with. */

#ifndef WC_ESGATE_DARWIN_H
#define WC_ESGATE_DARWIN_H

#include <stddef.h>
#include <stdint.h>

/* A string of the message: not NUL-terminated, valid while the message is retained. */
typedef struct wc_str {
    const char *data;
    size_t len;
} wc_str_t;

/* One AUTH_EXEC, copied out of the es_message_t by the handler. The argv and env buffers are
 * NUL-separated strings (argc/envc of them), malloc'd by the handler and freed when goESExec
 * returns: Go copies everything before it returns. */
typedef struct wc_exec {
    int32_t pid, ppid, pidversion;
    uint32_t euid, egid;
    int64_t start_sec, start_usec; /* process start time of the caller */
    wc_str_t caller_exe;           /* the image doing the exec */
    wc_str_t target_exe;           /* the image being exec'd (for a script: the interpreter) */
    wc_str_t script;               /* the script file, or {NULL, 0} */
    wc_str_t cwd;
    const char *argv;
    size_t argv_len;
    uint32_t argc;
    int argv_truncated; /* 1: argv did not fit WC_PACK_MAX bytes: a decision must not use it */
    const char *env;
    size_t env_len;
    uint32_t envc;
    int env_truncated;
    uint64_t target_dev, target_ino;
    uint32_t target_uid, target_mode;
    int64_t deadline_ms;    /* what is left of the message deadline when the handler ran */
    int is_platform_binary; /* the caller is an Apple-signed binary */
} wc_exec_t;

/* Results of wc_es_open. */
enum {
    WC_ES_OK = 0,
    WC_ES_ERR_BUSY,             /* a client is already open in this process */
    WC_ES_ERR_NOT_ENTITLED,     /* no com.apple.developer.endpoint-security.client (SIP on, no amfi_get_out_of_my_way) */
    WC_ES_ERR_NOT_PRIVILEGED,   /* not root */
    WC_ES_ERR_NOT_PERMITTED,    /* Full Disk Access / TCC */
    WC_ES_ERR_NO_DESCENDANTS,   /* es_new_descendants_client is not in this macOS */
    WC_ES_ERR_NO_DEADLINE_MODE, /* es_set_deadline_miss_mode is not in this macOS */
    WC_ES_ERR_SUBSCRIBE,
    WC_ES_ERR_OTHER
};

/* The macOS 27 symbols, resolved at run time so that this builds against older SDKs. The deadline
 * mode also needs the macOS 27 SDK at build time (the value of the mode comes from its header). */
int wc_es_has_descendants(void);
int wc_es_has_deadline_mode(void);

/* wc_es_open creates the client (descendants: es_new_descendants_client, else es_new_client),
 * sets the fail-closed deadline miss mode when fail_closed, raises the AUTH_EXEC deadline floor of
 * a descendants client to min_deadline_ms (es_set_deadline_min_milliseconds, macOS 27: "not
 * capped by the system default"; 0: leave it), subscribes to AUTH_EXEC and, when track_tree, to
 * NOTIFY_FORK and NOTIFY_EXIT. The handler calls goESExec / goESFork / goESExit
 * (esgate_darwin.go). On an error *err points at a static message. *floor_ms reports the
 * AUTH_EXEC minimum deadline the kernel confirmed (0 when not a descendants client). */
int wc_es_open(int descendants, int fail_closed, int track_tree, uint32_t min_deadline_ms, uint32_t *floor_ms, const char **err);

/* wc_es_respond answers an AUTH_EXEC (ALLOW when allow, else DENY; never cached) and releases
 * the message. Returns the es_respond_result_t (0 is success), -1 if the client is closed. */
int wc_es_respond(void *msg, int allow);

/* wc_es_close unsubscribes and deletes the client. Pending messages must have been answered. */
void wc_es_close(void);

#endif
