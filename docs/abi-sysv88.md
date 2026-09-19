# UNIX System V/88 R4.0 (m88k) — User-Mode Syscall ABI

Ground truth for the lead platform, recovered by disassembling the syscall
stubs in the machine's own `/usr/ccs/lib/libc.a` (same method runupc used for
the 3B1). Every fact below was read from real stub bytes, not assumed.

## Platform identity

- OS: **UNIX SYSTEM V/88 R40V4.4** (Motorola SysV/88, `/etc/motd`).
- Boards: MVME187 / MVME197 (`m187`/`m197` device names in `/etc/vfstab`).
- CPU: MC88100 (88110 on m197), big-endian.
- Executable format: **ELF 32-bit MSB, Machine = MC88000, SYSV, statically
  linked, not stripped, with debug_info** (confirmed via `readelf`/`file` on
  `/bin/cat`, `/bin/echo`, `/bin/ls`). No COFF for this release. Static linking
  means no shared-library relocation is needed for the first targets.

## Mounted filesystem layout (host side)

The guest disk is mounted on the host as two trees; the guest's `/etc/vfstab`
gives the mapping:

| Guest path | Host path             | Notes                                  |
|------------|-----------------------|----------------------------------------|
| `/`        | `/mnt/hd0_root`       | root filesystem (slice s2, `/dev/root`)|
| `/usr`     | `/mnt/hd0_slice3`     | s3 → `/usr` per vfstab                  |

**Symlink hazard (must special-case in the loader/fs layer):**
`/mnt/hd0_root/bin` is a symlink `bin -> /usr/bin`. On the host that dangles /
points at the wrong place; it must be interpreted as the guest `/usr/bin`,
i.e. resolve to **`/mnt/hd0_slice3/bin`**. More generally, the fs layer must
resolve guest-absolute symlink targets (`/usr/...`, `/var/...`, etc.) through
the guest mount table (`/ -> hd0_root`, `/usr -> hd0_slice3`), NOT through the
host's `/`. Other guest symlinks with absolute targets seen in `/usr`:
`adm -> /var/adm`, `mail -> /var/mail`, `tmp -> /adv4/tmp`, `pub ->
/usr/share/lib`, etc. — all need the same guest-root-relative resolution. This
is exactly the chroot-style path resolution runupc's `fs.zig` does, extended to
a small multi-mount table instead of a single root.

## Calling convention (`tb0 0, r0, 451`)

Recovered from `libc.a` members `write.o`, `read.o`, `open.o`, `close.o`,
`exit.o`. The stub shape:

```
    ; (some stubs first stash r2/r3 into r10/r11 around the trap)
    addu r9, r0, <N>     ; syscall number -> r9
    tb0  0, r0, 451      ; SYSCALL TRAP, vector 451 (0x1C3)  <- the trap
    br   err             ; instruction after the trap: the error path
    jmp  r1              ; success return (kernel skips the br to land here)
 err:
    ...                  ; errno bookkeeping, then
    br   _cerror         ; _cerror sets errno, returns -1
```

| Aspect            | Convention                                                   |
|-------------------|--------------------------------------------------------------|
| Trap instruction  | `tb0 0, r0, 451` → **exception vector 451** (0x1C3). `tb0 0,r0` always fires (bit 0 of r0 is always clear). |
| Syscall number    | In **r9** (`addu r9, r0, <N>`). NOT r13 (that's the BSD ABI).|
| Arguments         | In registers per the SVR4 m88k C calling convention: **r2..r8** (r9 holds the number). Stubs pass caller args straight through; the r10/r11 shuffle in read/write is just save/restore around the call, not the arg location. |
| Return value      | In **r2** (SVR4 m88k returns in r2). Second word likely r3.  |
| Error signalling  | Same skip-on-success mechanism as BSD/m88k: the word right after the trap is `br err`; on **success the kernel advances the pipeline past that `br`** so control reaches `jmp r1`; on **error the `br err` executes**. This is driven by the kernel adjusting the instruction pointers (sxip/snip/sfip), i.e. carry-flag / pipeline-pointer style. `_cerror` on the error path copies the kernel's error value into the global `errno` and returns -1. |

**Confidence:** HIGH for number register (r9), trap vector (451), and the
skip-on-success control flow — all read directly from five stubs. The exact
success/error signal the kernel uses (carry bit vs. a returned negative value)
should be double-checked when we service the trap: emulate "skip the `br` on
success, leave it on error" and verify against a real run (nono-mcp) if in
doubt. This mirrors the BSD `sxip/snip/sfip` handling documented in the
OpenBSD/NetBSD `m88100_syscall`.

## Comparison to BSD/m88k (why the personality split pays off)

| | SysV/88 R4 | OpenBSD/NetBSD m88k |
|-|------------|---------------------|
| Trap vector    | **451** | 128 |
| Number register| **r9**  | r13 |
| Args           | r2..r8  | r2..r12 |
| Return         | r2      | r2 (+r3) |
| Error signal   | skip-on-success (pipeline) | skip-on-success + carry |
| Format         | ELF32-BE| ELF32-BE |

The mechanism is structurally the same (a `tb0` trap, then `br err / jmp r1`),
so a single BSD-shaped trap-return handler parameterized by
`{syscall_vector, number_register}` covers both; only the syscall-number table
and errno table differ per OS.

## Syscall number table — RECOVERED

Authoritative source: the guest's own header
`/usr/include/sys/syscall.h` (Motorola MCG, `syscall.h 1.8`, 04 May 1993),
which enumerates numbers **1..146** with names and subcode notes. Verified
against a sweep of all 439 `libc.a` objects, matching `addu r9,r0,<N>` followed
by `tb0 0,r0,451`: **116 distinct numbers appear as real stubs** and every one
agrees with the header. The full table is encoded in
`src/syscalls/table_sysv88.zig`.

Highlights and gotchas:
- `SYS_sys3b` (50) in the header is the libc stub **`sysm88k`** — the m88k
  platform-control multiplexor (renamed from the 3B-series `sys3b`).
- `SYS_brk` (17) is the memory primitive (absolute new break), like the 3B1.
- Shared-number dual-return calls: getpid/getppid (20), getuid/geteuid (24),
  getgid/getegid (47) — second value in r3, as on the 3B1.
- Subcode multiplexors: `pgrpsys`(39), `signal`(48), `msgsys`(49), `sysm88k`(50),
  `shmsys`(52), `semsys`(53), `utssys`(57), `sysfs`(84), `context`(100). The
  first register arg selects the operation.
- **`select` = 146** was found ONLY in a libc stub; it is not in `syscall.h`.
  Capture it from the stub, not the header.
- Header-only (no libc stub, kernel-internal): `evsys`(101), `evtrapret`(102),
  `hrtsys`(109), `acancel`(110), `async`(111), `syssec`(145).
- There is also `/usr/include/ausyscall.h` (Addamax C2/security add-on), which
  uses the same base numbering.

First syscalls to implement (to run static `echo`/`cat`, then the shell and cc):
`exit`, `write`, `read`, `open`, `close`, `brk`, `lseek`, `stat`/`fstat`,
`getdents`, `access`, `ioctl`, `fcntl`, `dup`, `time`, `getpid`, then
`fork`/`execve`/`wait`/`pipe` for the shell and toolchain.

## Process startup contract (`_start`) — RECOVERED

Recovered by disassembling `crt1.o`'s `_start` and the fully-linked
`/bin/echo` entry in Ghidra (m88k:BE:32). Unlike the 3B1 (whose crt0 scans the
stack for argc/argv), SysV/88 hands the process arguments to `_start` **in
registers** — a clean register handoff, no stack walk, no auxv vector.

**Kernel → `_start` entry register state:**

| Register | Contents                                                        |
|----------|-----------------------------------------------------------------|
| r2       | **argc**                                                        |
| r3       | **argv** (`char **`, NULL-terminated vector)                    |
| r4       | **envp** (`char **`, NULL-terminated vector)                    |
| r6       | cleanup/termination function pointer, or 0 (crt passes it to `atexit` if non-zero) |
| r31      | **stack pointer** (8-byte aligned; the arg/env strings + pointer arrays live above it) |
| r1       | return address (crt ends with `jmp r1` after `exit`, as a safety net) |

Proof from the linked `echo` entry (0x200b0):
- `st.d r2,r31,0x20; st r4,r31,0x28` — saves entry r2,r3,r4 into the frame.
- `st r4, r2, 0x2540` with r2=0x30000 → stores entry **r4 into the global
  `_environ`** (0x32540). Confirms r4 = envp.
- Just before `bsr.n main`: `ld.d r2,r31,0x20; ld r4,r31,0x28` reloads
  r2=argc, r3=argv, r4=envp, so **`main(argc, argv, envp)` = `main(r2,r3,r4)`**
  (the SVR4 m88k C convention passes the first args in r2,r3,r4,...).

**What run88k's `process.zig` must do:**
1. Build the argv/envp **strings** and NULL-terminated **pointer arrays** in
   guest memory (a stack region near the top of the address space). These are
   the classic layout; the pointer vectors are what r3/r4 point at.
2. Set the entry registers: **r2 = argc, r3 = &argv[0], r4 = &envp[0]**,
   **r6 = 0**, **r31 = stack pointer** (8-byte aligned, below the arrays),
   **r1 = a halt/exit trampoline** address (so a stray `jmp r1` lands somewhere
   safe), and **pc/npc = entry point** from the ELF header.
3. No argc/argv words need to be *pushed* for the crt to read (it uses the
   registers), but keep the strings/vectors resident since `main` dereferences
   r3/r4. Placing a conventional `[argc][argv...][NULL][envp...][NULL][strings]`
   block and pointing r3 at argv[0] / r4 at envp[0] is the simplest correct
   layout and matches what the real kernel builds.

(The 88110 entry variant `crt0.o` is available in the project for cross-check if
a difference ever shows up; `crt1.o` is the one linked into these binaries.)

## Toolchain (the headline workload)

`/usr/ccs` is the C Compilation System: `cc`, `as`, `ld`, `cpp` (via cc),
`ccom`, `dump`, `dis`, `nm`, `size`, `ar`, plus `cof2elf`. `crt0.o`/`crt1.o`/
`crti.o`/`crtn.o` live in `/usr/ccs/lib`. `/usr/lib/libc.so.1` is the shared
libc; `/usr/ccs/lib/libc.a` is the static one. First toolchain target: compile
and link a trivial C program with the native `cc` driving its phases.
