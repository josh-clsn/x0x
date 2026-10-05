/*
 * W3-H (#1164) entropy and wall-clock shim. Linux, test processes only.
 *
 * Preloaded (LD_PRELOAD) into W3-H harness test processes by the nextest
 * `w3h` profile wrapper. It makes the two OS inputs that a single-process
 * simulation cannot otherwise control deterministic:
 *
 *  1. Entropy. getrandom(), getentropy() and syscall(SYS_getrandom, ...)
 *     return a seeded stream (W3H_ENTROPY_SEED, default 0x1164). Every
 *     Rust consumer in the lockfile reaches one of these: getrandom 0.2
 *     via syscall(SYS_getrandom), getrandom 0.3/0.4 and std (HashMap
 *     RandomState, which also seeds tokio's select! RNG) via getrandom().
 *     Crypto keys, signatures, nonces and every rand::ThreadRng become a
 *     function of the seed and the order of calls.
 *
 *  2. Wall clock. Once the harness calls w3h_shim_set_wall_offset_ns(),
 *     clock_gettime(CLOCK_REALTIME*) returns 2026-01-01T00:00:00Z plus the
 *     harness's virtual time. CLOCK_MONOTONIC is NOT changed: kernel waits
 *     with absolute monotonic deadlines (futex, condvars) must keep real
 *     time.
 *
 * Never load this into a production process: it removes all randomness.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t entropy_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t entropy_state;
static int entropy_seeded;

static uint64_t splitmix64(void) {
    uint64_t z = (entropy_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void fill(void *buf, size_t len) {
    unsigned char *out = (unsigned char *)buf;
    pthread_mutex_lock(&entropy_lock);
    if (!entropy_seeded) {
        const char *seed = getenv("W3H_ENTROPY_SEED");
        entropy_state = seed ? strtoull(seed, NULL, 0) : 0x1164ULL;
        entropy_seeded = 1;
    }
    while (len > 0) {
        uint64_t word = splitmix64();
        size_t n = len < sizeof word ? len : sizeof word;
        memcpy(out, &word, n);
        out += n;
        len -= n;
    }
    pthread_mutex_unlock(&entropy_lock);
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    (void)flags;
    fill(buf, buflen);
    return (ssize_t)buflen;
}

int getentropy(void *buffer, size_t length) {
    if (length > 256) {
        errno = EIO;
        return -1;
    }
    fill(buffer, length);
    return 0;
}

long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);
    if (number == SYS_getrandom) {
        fill((void *)a1, (size_t)a2);
        return a2;
    }
    static long (*real_syscall)(long, ...);
    if (!real_syscall) {
        real_syscall = (long (*)(long, ...))dlsym(RTLD_NEXT, "syscall");
    }
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}

/* 2026-01-01T00:00:00Z */
static const uint64_t WALL_BASE_SECS = 1767225600ULL;
static atomic_int wall_active;
static atomic_uint_fast64_t wall_offset_ns;

/* Exported for the harness (found with dlsym(RTLD_DEFAULT, ...)). */
void w3h_shim_set_wall_offset_ns(uint64_t offset_ns) {
    atomic_store(&wall_offset_ns, offset_ns);
    atomic_store(&wall_active, 1);
}

unsigned int w3h_shim_version(void) { return 1; }

int clock_gettime(clockid_t clockid, struct timespec *tp) {
    if (atomic_load(&wall_active) &&
        (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE)) {
        uint64_t offset = atomic_load(&wall_offset_ns);
        tp->tv_sec = (time_t)(WALL_BASE_SECS + offset / 1000000000ULL);
        tp->tv_nsec = (long)(offset % 1000000000ULL);
        return 0;
    }
    static int (*real_clock_gettime)(clockid_t, struct timespec *);
    if (!real_clock_gettime) {
        real_clock_gettime =
            (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    }
    return real_clock_gettime(clockid, tp);
}
