/*
 * W3-H (#1164) entropy and wall-clock shim. Linux (x86_64, aarch64), test
 * processes only.
 *
 * Loaded with LD_PRELOAD by the nextest `w3h` profile wrapper. It does
 * NOTHING unless the process environment sets both
 *     W3H_SHIM_ACTIVE=1   and   W3H_ENTROPY_SEED=<integer>
 * when the library is loaded; otherwise every interposed call passes
 * straight through to the kernel / libc and w3h_shim_active() returns 0.
 *
 * When active it makes the two OS inputs a single-process simulation cannot
 * otherwise control deterministic:
 *
 *  1. Entropy. getrandom(), getentropy() and syscall(SYS_getrandom, ...)
 *     return a SplitMix64 stream seeded by W3H_ENTROPY_SEED (not a CSPRNG:
 *     test processes only). Rust consumers in the lockfile reach one of
 *     these: getrandom 0.2 via syscall(SYS_getrandom), getrandom 0.3/0.4
 *     and std (HashMap RandomState, which also seeds tokio's select! RNG)
 *     via getrandom().
 *
 *  2. Wall clock. Once the harness calls w3h_shim_set_wall_offset_ns(),
 *     clock_gettime(CLOCK_REALTIME*) returns 2026-01-01T00:00:00Z plus the
 *     harness's virtual time. CLOCK_MONOTONIC is NOT changed: kernel waits
 *     with absolute monotonic deadlines (futex, condvars) keep real time.
 *
 * syscall() is interposed by an assembly trampoline that never reads
 * variadic arguments in C: SYS_getrandom is redirected with its three
 * register arguments; every other number is forwarded exactly as glibc's
 * own syscall.S does (registers shifted, arg 6 from the caller's stack
 * slot), so arbitrary-arity syscalls are passed through unchanged.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
#ifndef GRND_RANDOM
#define GRND_RANDOM 0x0002
#endif
#ifndef GRND_INSECURE
#define GRND_INSECURE 0x0004
#endif

#define W3H_HIDDEN __attribute__((visibility("hidden")))
#define W3H_STR2(x) #x
#define W3H_STR(x) W3H_STR2(x)

/* ---- raw kernel entry (glibc-identical syscall semantics) ------------- */

/* long w3h_raw_syscall(long number, ...): glibc syscall() semantics
 * (-1 + errno on failure), implemented in assembly without va_arg. */
W3H_HIDDEN long w3h_raw_syscall(long number, ...);
/* errno = err; return -1. Tail-called from the assembly error path. */
W3H_HIDDEN long w3h_syscall_error(long err);
/* The SYS_getrandom arm of the interposed syscall(). */
W3H_HIDDEN long w3h_getrandom_syscall(void *buf, size_t len, unsigned int flags);

long w3h_syscall_error(long err) {
    errno = (int)err;
    return -1;
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl w3h_raw_syscall\n"
    ".hidden w3h_raw_syscall\n"
    ".type w3h_raw_syscall,@function\n"
    "w3h_raw_syscall:\n"
    "    movq %rdi, %rax\n"
    "    movq %rsi, %rdi\n"
    "    movq %rdx, %rsi\n"
    "    movq %rcx, %rdx\n"
    "    movq %r8, %r10\n"
    "    movq %r9, %r8\n"
    "    movq 8(%rsp), %r9\n"
    "    syscall\n"
    "    cmpq $-4095, %rax\n"
    "    jae 1f\n"
    "    ret\n"
    "1:\n"
    "    negq %rax\n"
    "    movq %rax, %rdi\n"
    "    jmp w3h_syscall_error\n"
    ".size w3h_raw_syscall, .-w3h_raw_syscall\n"
    "\n"
    ".globl syscall\n"
    ".type syscall,@function\n"
    "syscall:\n"
    "    cmpq $" W3H_STR(SYS_getrandom) ", %rdi\n"
    "    jne w3h_raw_syscall\n"
    "    movq %rsi, %rdi\n"
    "    movq %rdx, %rsi\n"
    "    movl %ecx, %edx\n"
    "    jmp w3h_getrandom_syscall\n"
    ".size syscall, .-syscall\n");
#elif defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl w3h_raw_syscall\n"
    ".hidden w3h_raw_syscall\n"
    ".type w3h_raw_syscall,%function\n"
    "w3h_raw_syscall:\n"
    "    uxtw x8, w0\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    mov x2, x3\n"
    "    mov x3, x4\n"
    "    mov x4, x5\n"
    "    mov x5, x6\n"
    "    svc #0\n"
    "    cmn x0, #4095\n"
    "    b.cs 1f\n"
    "    ret\n"
    "1:\n"
    "    neg x0, x0\n"
    "    b w3h_syscall_error\n"
    ".size w3h_raw_syscall, .-w3h_raw_syscall\n"
    "\n"
    ".globl syscall\n"
    ".type syscall,%function\n"
    "syscall:\n"
    "    cmp x0, #" W3H_STR(SYS_getrandom) "\n"
    "    b.ne w3h_raw_syscall\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    mov w2, w3\n"
    "    b w3h_getrandom_syscall\n"
    ".size syscall, .-syscall\n");
#else
#error "w3h_shim supports x86_64 and aarch64 Linux only"
#endif

/* ---- activation ------------------------------------------------------- */

static atomic_int shim_active;
static atomic_ulong entropy_calls;

static pthread_mutex_t entropy_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t entropy_state;

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
static _Atomic(clock_gettime_fn) real_clock_gettime;

__attribute__((constructor)) static void w3h_shim_init(void) {
    /* Constructors run single-threaded, before the Rust runtime starts, so
     * the resolution below cannot race a caller. Any call that arrives
     * before this point sees `shim_active == 0` / a NULL resolver and takes
     * the raw-syscall pass-through, so dlsym is never re-entered from an
     * interposed call. */
    void *resolved = dlsym(RTLD_NEXT, "clock_gettime");
    if (resolved != NULL) {
        clock_gettime_fn fn;
        memcpy(&fn, &resolved, sizeof fn);
        atomic_store(&real_clock_gettime, fn);
    }
    const char *active = getenv("W3H_SHIM_ACTIVE");
    const char *seed = getenv("W3H_ENTROPY_SEED");
    if (active == NULL || strcmp(active, "1") != 0 || seed == NULL || *seed == '\0') {
        return;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(seed, &end, 0);
    if (errno != 0 || end == NULL || *end != '\0') {
        return;
    }
    entropy_state = (uint64_t)value;
    atomic_store(&shim_active, 1);
}

/* ---- entropy ---------------------------------------------------------- */

static uint64_t splitmix64(void) {
    uint64_t z = (entropy_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void fill(void *buf, size_t len) {
    unsigned char *out = (unsigned char *)buf;
    pthread_mutex_lock(&entropy_lock);
    while (len > 0) {
        uint64_t word = splitmix64();
        size_t n = len < sizeof word ? len : sizeof word;
        memcpy(out, &word, n);
        out += n;
        len -= n;
    }
    pthread_mutex_unlock(&entropy_lock);
    atomic_fetch_add(&entropy_calls, 1);
}

long w3h_getrandom_syscall(void *buf, size_t len, unsigned int flags) {
    if (!atomic_load(&shim_active)) {
        return w3h_raw_syscall(SYS_getrandom, buf, len, flags);
    }
    /* Linux getrandom(2) contract for an always-ready source: unknown flag
     * bits and GRND_RANDOM|GRND_INSECURE are EINVAL; a NULL buffer with a
     * non-zero length is EFAULT; otherwise the full request is served. */
    if ((flags & ~(unsigned int)(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE)) != 0 ||
        ((flags & GRND_RANDOM) && (flags & GRND_INSECURE))) {
        return w3h_syscall_error(EINVAL);
    }
    if (buf == NULL && len > 0) {
        return w3h_syscall_error(EFAULT);
    }
    if (len > 0) {
        fill(buf, len);
    }
    return (long)len;
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    return (ssize_t)w3h_getrandom_syscall(buf, buflen, flags);
}

int getentropy(void *buffer, size_t length) {
    if (length > 256) {
        errno = EIO;
        return -1;
    }
    if (!atomic_load(&shim_active)) {
        unsigned char *out = (unsigned char *)buffer;
        while (length > 0) {
            long got = w3h_raw_syscall(SYS_getrandom, out, length, 0);
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            out += got;
            length -= (size_t)got;
        }
        return 0;
    }
    if (buffer == NULL && length > 0) {
        errno = EFAULT;
        return -1;
    }
    fill(buffer, length);
    return 0;
}

/* ---- wall clock ------------------------------------------------------- */

/* 2026-01-01T00:00:00Z */
static const uint64_t WALL_BASE_SECS = 1767225600ULL;
static atomic_int wall_active;
static atomic_uint_fast64_t wall_offset_ns;

/* Exported for the harness (found with dlsym(RTLD_DEFAULT, ...)). */
unsigned int w3h_shim_version(void) { return 2; }

int w3h_shim_active(void) { return atomic_load(&shim_active); }

unsigned long w3h_shim_entropy_calls(void) { return atomic_load(&entropy_calls); }

void w3h_shim_set_wall_offset_ns(uint64_t offset_ns) {
    if (!atomic_load(&shim_active)) {
        return;
    }
    atomic_store(&wall_offset_ns, offset_ns);
    atomic_store(&wall_active, 1);
}

int clock_gettime(clockid_t clockid, struct timespec *tp) {
    if (atomic_load(&wall_active) &&
        (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE)) {
        /* glibc declares `tp` nonnull; a NULL here is the caller's UB, as
         * with the real clock_gettime. */
        uint64_t offset = atomic_load(&wall_offset_ns);
        tp->tv_sec = (time_t)(WALL_BASE_SECS + offset / 1000000000ULL);
        tp->tv_nsec = (long)(offset % 1000000000ULL);
        return 0;
    }
    clock_gettime_fn real = atomic_load(&real_clock_gettime);
    if (real != NULL) {
        return real(clockid, tp);
    }
    /* Before the constructor (or if dlsym failed): the kernel directly. */
    return (int)w3h_raw_syscall(SYS_clock_gettime, (long)clockid, tp);
}
