/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2012-2017 Benjamin Fleischer
 * Copyright (c) 2018 Syncplicity by Axway
 * All rights reserved.
 */

#ifndef _FUSE_LOCKING_H_
#define _FUSE_LOCKING_H_

#include "fuse.h"

#include "fuse_node.h"

#include <libkern/locks.h>

#if FUSE_TRACE_LK || M_OSXFUSE_ENABLE_STATIC_LOGMSG
#  include <sys/vm.h>
#endif

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
#  include <kern/thread.h>
#endif

enum fusefslocktype {
    FUSEFS_SHARED_LOCK    = 1,
    FUSEFS_EXCLUSIVE_LOCK = 2
};

#if __LP64__
#  define FUSEFS_SHARED_OWNER (void *)0xffffffffffffffff
#else
#  define FUSEFS_SHARED_OWNER (void *)0xffffffff
#endif

#if M_OSXFUSE_ENABLE_AUX_FSNODE_LOCK

#  if M_OSXFUSE_ENABLE_AUX_LOCK_LOGGING
#    define trace_aux_enter(op, nodeid, context) tracenode(nodeid, #op" AUX: %s {", context)
#    define trace_aux_exit(op, nodeid, context)  tracenode(nodeid, "} " #op " AUX: %s", context)

#    define trace_with_aux_enter(enter_op, cp, context) \
    tracenode(cp->nodeid, "with_aux_" #enter_op " (owner = %0llx): %s {", \
              (cp->aux_nodelockowner ? thread_tid(cp->aux_nodelockowner) : 0), context)

#    define trace_with_aux_exit(exit_op, cp, context) tracenode(cp->nodeid, "} with_aux_" #exit_op " %s", context)

#  else

#    define trace_aux_enter(op, nodeid, context)
#    define trace_aux_exit(op, nodeid, context)

#    define trace_with_aux_enter(enter_op, cp, context) (void)(0)
#    define trace_with_aux_exit(exit_op, cp, context) (void)(0)
#  endif


#  define fusefs_lock_aux(cp, context, thread)               \
    ({                                                       \
        thread_t la_thread_ = (thread);                      \
        trace_aux_enter(lock, cp->nodeid, context);          \
        fuse_lck_mtx_lock(cp->aux_nodelock);                 \
        cp->aux_nodelockowner = la_thread_;                  \
        trace_aux_exit(lock, cp->nodeid, context);           \
    })

#  define fusefs_unlock_aux(cp, context, thread...)         \
    ({                                                      \
        trace_aux_enter(unlock, cp->nodeid, context);       \
        cp->aux_nodelockowner = NULL;                       \
        fuse_lck_mtx_unlock(cp->aux_nodelock);              \
        trace_aux_exit(unlock, cp->nodeid, context);        \
    })

#  define fusefs_ensure_unlock_aux(cp, context, thread...)              \
    ({                                                                  \
        bool eau_r_ = false;                                            \
        thread_t eau_thread_ = (((void*)thread+0) ?: current_thread());  \
        if (cp->aux_nodelockowner == eau_thread_) {                     \
            fusefs_unlock_aux(cp, context);                             \
            eau_r_ = true;                                              \
        }                                                               \
        eau_r_;                                                         \
    })

#  define fusefs_ensure_lock_aux(cp, context, thread...)                \
    ({                                                                  \
        bool eal_r_ = false;                                            \
        thread_t eal_thread_ = (((void*)thread+0) ?: current_thread());  \
        if (cp->aux_nodelockowner != eal_thread_) {                     \
            fusefs_lock_aux(cp, context, eal_thread_);                  \
            eal_r_ = true;                                              \
        }                                                               \
        eal_r_;                                                         \
    })

#define with_aux_(enter_op, exit_op, cp, context, thread...)            \
    FUSE_PP_WITH_PREFIX()                                               \
    FUSE_PP_WITH_ACTION(struct fuse_vnode_data* wau_cp_ = cp)           \
    FUSE_PP_WITH_ACTION(thread_t wau_thread_ = (((void*)thread+0) ?: current_thread())) \
    FUSE_PP_WITH_ACTION(bool wau_do_cleanup_ = (trace_with_aux_enter(enter_op, wau_cp_, context), fusefs_ensure_ ##enter_op## _aux(wau_cp_, context, wau_thread_)), \
               (!wau_do_cleanup_ ?: fusefs_##exit_op## _aux(wau_cp_, context, wau_thread_), trace_with_aux_exit(enter_op, wau_cp_, context))) \
    FUSE_PP_WITH_SUFFIX()

#  define with_aux_lock(cp, context, thread...)    with_aux_(lock, unlock, cp, context, ##thread)
#  define with_aux_unlock(cp, context, thread...)  with_aux_(unlock, lock, cp, context, ##thread)

#else

#  define fusefs_lock_aux(cp, context, thread)
#  define fusefs_unlock_aux(cp, context)
#  define fusefs_ensure_unlock_aux(cp, context, thread...)
#  define fusefs_ensure_lock_aux(cp, context, thread...)

#  define with_aux_lock(cp, context, thread...)
#  define with_aux_unlock(cp, context, thread...)

#endif /* M_OSXFUSE_ENABLE_AUX_FSNODE_LOCK */


/* Locking */
extern int fusefs_lock(fusenode_t, enum fusefslocktype);
extern int fusefs_lockpair(fusenode_t, fusenode_t, enum fusefslocktype);
extern int fusefs_lockfour(fusenode_t, fusenode_t, fusenode_t, fusenode_t,
                           enum fusefslocktype);
extern void fusefs_lock_truncate(fusenode_t, lck_rw_type_t);

/* Unlocking */
extern void fusefs_unlock(fusenode_t);
extern void fusefs_unlockpair(fusenode_t, fusenode_t);
extern void fusefs_unlockfour(fusenode_t, fusenode_t, fusenode_t, fusenode_t);
extern void fusefs_unlock_truncate(fusenode_t);

/* Wish the kernel exported lck_rw_done()... */
extern void fusefs_lck_rw_done(lck_rw_t *);

extern lck_attr_t     *fuse_lock_attr;
extern lck_grp_attr_t *fuse_group_attr;
extern lck_grp_t      *fuse_lock_group;
extern lck_mtx_t      *fuse_device_mutex;

#ifdef FUSE_TRACE_LK

#define fuse_lck_mtx_lock(m)                                                  \
    {                                                                         \
        proc_t __FUNCTION__ ## p = current_proc();                            \
        IOLog("0: lck_mtx_lock(%p): %s@%d by %d\n", (m), __FUNCTION__,        \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
        lck_mtx_lock((m));                                                    \
        IOLog("1: lck_mtx_lock(%p): %s@%d by %d\n", (m), __FUNCTION__,        \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
    }

#define fuse_lck_mtx_unlock(m)                                                \
    {                                                                         \
        proc_t __FUNCTION__ ## p = current_proc();                            \
        IOLog("1: lck_mtx_unlock(%p): %s@%d by %d\n", (m), __FUNCTION__,      \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
        lck_mtx_unlock((m));                                                  \
        IOLog("0: lck_mtx_unlock(%p): %s@%d by %d\n", (m), __FUNCTION__,      \
           __LINE__, (__FUNCTION__ ## p) ? proc_pid(__FUNCTION__ ## p) : 0);  \
    }

#define fuse_lck_rw_lock_shared(l)      lck_rw_lock_shared((l))
#define fuse_lck_rw_lock_exclusive(l)   lck_rw_lock_exclusive((l))
#define fuse_lck_rw_unlock_shared(l)    lck_rw_unlock_shared((l))
#define fuse_lck_rw_unlock_exclusive(l) lck_rw_unlock_exclusive((l))

#else /* !FUSE_TRACE_LK */

#define fuse_lck_mtx_lock(m)            lck_mtx_lock((m))
#define fuse_lck_mtx_unlock(m)          lck_mtx_unlock((m))

#define fuse_lck_rw_lock_shared(l)      lck_rw_lock_shared((l))
#define fuse_lck_rw_lock_exclusive(l)   lck_rw_lock_exclusive((l))
#define fuse_lck_rw_unlock_shared(l)    lck_rw_unlock_shared((l))
#define fuse_lck_rw_unlock_exclusive(l) lck_rw_unlock_exclusive((l))

#define fuse_lck_mtx_try_lock(l)        IOLockTryLock((IOLock *)l)

#endif /* FUSE_TRACE_LK */

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

typedef struct _fusefs_recursive_lock fusefs_recursive_lock;

extern fusefs_recursive_lock* fusefs_recursive_lock_alloc(void);
extern fusefs_recursive_lock* fusefs_recursive_lock_alloc_with_maxcount(UInt32);
extern void fusefs_recursive_lock_free(fusefs_recursive_lock *lock);
extern void fusefs_recursive_lock_lock(fusefs_recursive_lock *lock);
extern void fusefs_recursive_lock_unlock(fusefs_recursive_lock *lock);
extern bool fusefs_recursive_lock_have_lock(fusefs_recursive_lock *lock);

#if M_OSXFUSE_ENABLE_LOCK_LOGGING || M_OSXFUSE_ENABLE_STATIC_LOGMSG
extern lck_mtx_t *fuse_log_lock;
#endif

#if M_OSXFUSE_ENABLE_STATIC_LOGMSG

#define LOGMSG_BUF_SIZE 512
extern char logmsg_buf[LOGMSG_BUF_SIZE];

#define tracemsg(argfmt, args...)  logmsg("%s(): " argfmt, __FUNCTION__, ##args)
#define tracenode(nodeid, argfmt, args...) logmsg("NODE[%lld]: %s() -- " argfmt, (uint64_t)nodeid, __FUNCTION__, ##args)

static inline void logmsg(const char* fmt, ...)
{
    lck_mtx_lock(fuse_log_lock);

    struct proc *p = current_proc();
    int pid = p ? proc_pid(p) : 0;
    int pfx_len = (int)strlcpy(logmsg_buf, "PROC[", LOGMSG_BUF_SIZE);

    if (pid > 0) {
        proc_name(pid, logmsg_buf+pfx_len, LOGMSG_BUF_SIZE-pfx_len);
        pfx_len = (int)strlen(logmsg_buf);
        if (pfx_len >= sizeof(logmsg_buf)) {
            pfx_len = sizeof(logmsg_buf) - 1;
        }
    }

    pfx_len += snprintf(logmsg_buf+pfx_len, LOGMSG_BUF_SIZE-pfx_len, "][%d] -- ", pid > 0 ? pid : -1 );
    if (pfx_len >= sizeof(logmsg_buf)) {
        pfx_len = sizeof(logmsg_buf) - 1;
    }

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(logmsg_buf+pfx_len, sizeof(logmsg_buf)-pfx_len, fmt, vl);
    va_end(vl);

    kprintf("%s\n", logmsg_buf);
    lck_mtx_unlock(fuse_log_lock);
}

#else

#define tracemsg(argfmt, args...)
#define tracenode(nodeid, argfmt, args...)
static inline void logmsg(const char* fmt, ...) { }

#endif  /* M_OSXFUSE_ENABLE_STATIC_LOGMSG */

#if M_OSXFUSE_ENABLE_LOCK_LOGGING

#define rawlog(msg, args...) IOLog(msg, ##args)

#define log(fmt, args...) \
	do { \
		lck_mtx_lock(fuse_log_lock); \
		rawlog(fmt, ##args); \
		rawlog("\n"); \
		lck_mtx_unlock(fuse_log_lock); \
	} while(0)

#define log_enter(params_format, args...) \
	do { \
		lck_mtx_lock(fuse_log_lock); \
		rawlog("[%s:%d] Entering %s: ", __FILE__, __LINE__, __FUNCTION__); \
		rawlog(params_format, ##args); \
		rawlog("\n"); \
		lck_mtx_unlock(fuse_log_lock); \
	} while(0)

#define log_leave(return_format, args...) \
	do { \
		lck_mtx_lock(fuse_log_lock); \
		rawlog("[%s:%d] Leaving %s: ", __FILE__, __LINE__, __FUNCTION__); \
		rawlog(return_format, ##args); \
		rawlog("\n"); \
		lck_mtx_unlock(fuse_log_lock); \
	} while(0)
#else /* !M_OSXFUSE_ENABLE_LOCK_LOGGING */
#define log(fmt, args...) do {} while(0)
#define log_enter(params_format, args...) do {} while(0)
#define log_leave(return_format, args...) do {} while(0)
#endif /* M_OSXFUSE_ENABLE_LOCK_LOGGING */

#if M_OSXFUSE_ENABLE_HUGE_LOCK

extern fusefs_recursive_lock *fuse_huge_lock;

#define fuse_hugelock_lock() \
	do { \
		log("%s thread=%p: Aquiring huge lock %p...", __FUNCTION__, current_thread(), fuse_huge_lock); \
		fusefs_recursive_lock_lock(fuse_huge_lock); \
		log("%s thread=%p: huge lock %p aquired!", __FUNCTION__, current_thread(), fuse_huge_lock); \
	} while(0)

#define fuse_hugelock_unlock() \
	do { \
		log("%s thread=%p: Releasing huge lock %p...", __FUNCTION__, current_thread(), fuse_huge_lock); \
		fusefs_recursive_lock_unlock(fuse_huge_lock); \
		log("%s thread=%p: huge lock %p released!", __FUNCTION__, current_thread(), fuse_huge_lock); \
	} while(0)

#define fuse_hugelock_have_lock() fusefs_recursive_lock_have_lock(fuse_huge_lock)

#define fuse_biglock_lock(lock) fuse_hugelock_lock()
#define fuse_biglock_unlock(lock) fuse_hugelock_unlock()
#define fuse_biglock_have_lock(lock) fuse_hugelock_have_lock()

#elif M_OSXFUSE_ENABLE_BIG_LOCK

typedef fusefs_recursive_lock fuse_biglock_t;

#define fuse_biglock_alloc() fusefs_recursive_lock_alloc_with_maxcount(1)
#define fuse_biglock_free(lock) fusefs_recursive_lock_free(lock)

#define fuse_biglock_lock(lock) \
	do { \
		log("%s thread=%p: Aquiring biglock %p...", __FUNCTION__, current_thread(), lock); \
		fusefs_recursive_lock_lock(lock); \
		log("%s thread=%p: biglock %p aquired!", __FUNCTION__, current_thread(), lock); \
	} while(0)

#define fuse_biglock_unlock(lock) \
	do { \
		log("%s thread=%p: Releasing biglock %p...", __FUNCTION__, current_thread(), lock); \
		fusefs_recursive_lock_unlock(lock); \
		log("%s thread=%p: biglock %p released!", __FUNCTION__, current_thread(), lock); \
	} while(0)

#define fuse_biglock_have_lock(lock) fusefs_recursive_lock_have_lock(lock)

#else /* !M_OSXFUSE_ENABLE_HUGO_LOCK && !M_OSXFUSE_ENABLE_BIG_LOCK */

#define fuse_biglock_lock(lock) do {} while(0)
#define fuse_biglock_unlock(lock) do {} while(0)
#define fuse_biglock_have_lock(lock) false

#endif /* M_OSXFUSE_ENABLE_HUGE_LOCK, M_OSXFUSE_ENABLE_BIG_LOCK */

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

#endif /* _FUSE_LOCKING_H_ */
