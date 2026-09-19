# Dynamic linking (SysV/88 m88k) — status

Most of the SysV/88 userland is dynamically linked: `date`, and the whole
toolchain (`cc`, `as`, `ld`), plus ~76% of `/usr/bin`. Only a handful (echo,
cat, pwd, ls) are static. So dynamic linking is required for the headline goal
(running the compiler), not optional.

## What run88k implements (src/loaders/dynamic.zig)

A loader-side runtime linker (our own ld.so) with **eager binding**:

1. `elf.load` maps the main executable (bias 0) and reports `is_dynamic` +
   the PT_DYNAMIC vaddr.
2. `dynamic.link` reads PT_DYNAMIC, then breadth-first loads each `DT_NEEDED`
   library through the guest mount table (fs.resolve) at successive load
   biases (0x05000000, +0x00800000 each).
3. It collects every object's dynamic tables (STRTAB/SYMTAB/HASH/RELA/JMPREL)
   and applies relocations for all objects:
   - **R_88K_RELATIVE (16)**: `*addr += bias` (libc.so.1 has 750 of these).
   - **R_88K_JMP_SLOT (2)**: resolve the function symbol across all objects and
     write its final address into the GOT slot (eager; no lazy PLT trampoline).
   - **R_88K_COPY (1)**: copy the defining library's bytes for the symbol into
     the executable's .bss (`__iob`, `errno`, `__ctype`, ...).
   - generic data/abs: `*addr = sym_value + addend`.

Symbol lookup walks all loaded objects' `.dynsym` (non-UNDEF entries), using the
ELF hash table's `nchain` as the symbol count.

## Verified so far

- date's dependency graph (libsocket.so.1, libnsl.so, libc.so.1) loads and
  maps; relocations apply without an unresolved-symbol error; control transfers
  INTO libc code (previously it jumped through a null GOT slot to pc=4).

## Status: dynamic linking works; `date` runs without faulting

The dynamic linker now loads date's full dependency graph, applies all
relocations, and runs libc code end-to-end without faulting. Three runtime-
linker responsibilities beyond relocation were required and are implemented:

1. **COPY-relocation symbol preemption.** COPY-relocated symbols in the exe
   (`__iob`, `errno`, `__ctype`, ...) are recorded as preemptions so named
   relocations in all objects resolve to the exe's copy.
2. **The `struct link_map` chain.** SysV/88's shared libc is also the
   interpreter and keeps a chain of `struct link_map` (link.h: l_addr, l_name,
   l_ld, l_next@0xc, l_prev) rooted at libc's `__first_link[0]`. e.g. `fflush`
   walks it. `buildLinkMap()` synthesizes this chain (one entry per loaded
   object) and publishes the head into `__first_link`.
3. **The break-tracking global `_nd`.** libc's `_sbrk`/`_brk` cache the current
   break in the userland global `_nd` (libc `.data`). The real ld.so seeds it
   with the initial break; without that, `_sbrk` computes from 0 and malloc
   walks into negative addresses. The linker now writes the exe's initial brk
   into `_nd`.

Also: `brk` below the heap base is a success no-op (sbrk probes), and the mmap
bump-region is kept clear of the library load area.

## Symbol preemption for library GOT slots (RELATIVE relocs) — DONE

The final general piece: a library's GOT slot filled by a nameless RELATIVE
reloc that targets one of the library's OWN exported data symbols must be
redirected to the EXECUTABLE's definition when the exe also exports that symbol
(ELF symbol preemption). `preemptLibraryData()` correlates each library
RELATIVE reloc's target vaddr to a library `.dynsym` symbol, and if the exe
defines the same name, overwrites the GOT slot with the exe's address.

This fixed `getopt`: date defines `optind`/`optarg`/`optopt`, and libc's getopt
reads them via GOT slots that RELATIVE-relocated to libc's own copies. After
preemption, libc's getopt uses date's `optind` (=1), and `getopt` correctly
returns -1 for no-args (was returning 1 → wrong branch). Also preempts `__iob`,
`tzname`, `daylight`, `_lib_version`, etc.

## Where dynamic linking stands

Fully implemented and correct: segment mapping with bias, NEEDED-lib loading,
RELATIVE/JMP_SLOT/COPY/generic relocations, cross-object symbol resolution,
COPY-reloc + RELATIVE-GOT symbol preemption, the `struct link_map` chain
(`__first_link`), and the `_nd` break global. date now runs its entire crt +
libc startup, `setlocale`/`setcat`/`setlabel`/`time`/`getopt` all execute,
getopt returns correctly, and stdout is set up (fstat/ioctl on fd 1). Static
binaries are unaffected.

## Remaining (narrow): `date` produces no visible output

date runs its whole startup, does `time`/`fstat(1)`/`ioctl(1, TCGETA)`, then
`exit(0)` — with no `write`. It reaches main and the post-getopt path, sets up
stdout, but the formatted date is never written. Candidates:
  - `strftime`/`localtime` returns an empty result (timezone/locale data not
    found — date reads /etc/TIMEZONE or TZ; localtime calls `time` repeatedly
    during tzset). Needs tracing localtime/strftime output.
  - the output is buffered in stdio and the exit-time fflush doesn't emit it
    (the link_map walk works now, but the FILE's buffer/state may be wrong).
This is date-specific application/stdio behavior, not a linking defect — the
dynamic linker and startup contract are complete. Next: trace inside
localtime/strftime to see whether the date string is produced, and whether the
stdout FILE buffers correctly.

## (historical) Diagnosis notes — COPY-relocation symbol preemption

Ruled OUT the r25/GOT-base theory below: verified our core sets r25 correctly to
libc's biased PLTGOT (0x6062c20) via the PC-relative `bsr.n; addu r25,r25,r1`
idiom, and `bsr.n` sets r1 = pc+8 correctly. Relocations (RELATIVE/JMP_SLOT)
apply correctly too (verified r21 = a correctly-biased libc data pointer).

The actual fault: date calls **`fflush`** (libc 0x2e8c0), which walks the stdio
`__iob` FILE table. `__iob` is a **COPY relocation** in date (`.rela.bss`, 640
bytes): the exe reserves space in ITS .bss for `__iob` and the runtime linker
must (a) copy the library's initial bytes there AND (b) make EVERY reference to
`__iob` — including libc's own — resolve to the EXECUTABLE's copy, not the
library's. This is ELF "copy relocation / symbol preemption": a definition in
the main executable preempts the same-named definition in a library.

Our linker resolves symbols but does NOT implement preemption ordering, so
libc's internal reference to `__iob` still points at libc's own (uninitialized)
copy → fflush walks a zero/garbage table → dereferences ~null (addr 0xc).

**Partial fix applied:** dynamic.zig now records COPY-relocated symbols as
preemptions and resolves NAMED (JMP_SLOT / data) relocations to the exe's copy.
This is correct and necessary, but does not by itself fix `date`.

**Remaining subtlety (characterized):** libc references its own `__iob` through
`GOT[0x1c4]`, and that GOT slot is filled by a **RELATIVE** relocation
(`*slot += bias`) pointing at libc's OWN copy in libc `.data` (0x617f4) — a
relocation with no symbol name, so preemption can't intercept it by name. So
after our link, libc still walks its own uninitialized `__iob`, and `fflush`
dereferences ~null.

To finish, the linker must make libc's `__iob` GOT slot point at the exe's
copy. Options:
  - Map each library GOT slot back to the symbol it addresses (via the lib's own
    non-RELATIVE symbol relocs or by matching the RELATIVE target vaddr to a
    `.dynsym` st_value), then, for preempted symbols, overwrite the slot with
    the exe's address. Requires correlating RELATIVE targets to symbols.
  - Or implement copy relocations the SysV/88 way: rather than copying into the
    exe, point the exe's references at the library's definition (inverse of
    mainstream ELF) — needs confirmation from the 88open psABI.
This is the last identified step to run dynamic binaries; static binaries are
unaffected and continue to work.

## (Investigated, NOT the cause) the m88k PIC data-base register

date now faults **inside libc** at a data-scanning loop that indexes off
register **r25** (e.g. `ld r21, r25, 0x1c4`). r25 is the shared library's
data/GOT base pointer. On m88k SysV PIC, library code is r25-relative, and r25
must hold the library's own GOT/data base on entry to its functions.

The per-symbol PLT stub does NOT set r25 (verified by disassembly): it only
loads the function address from the GOT and `jmp`s. So r25 must be established
another way — likely:
  - set by the crt/`_start` for the main object, and/or
  - each PIC function loads r25 from a fixed GOT reference in its prologue, and
    the value we need is the correct per-library GOT base.

Because our eager binding jumps straight to the resolved libc function, whatever
normally establishes r25 for library calls is not happening. Determining the
exact m88k SysV convention for the GOT-base register (r25) — and setting it
correctly per-object on entry — is the remaining work. This needs the 88open
SVR4 m88k psABI (PIC/GOT chapter) and/or differential tracing of a real call
through nono.

## Options to finish

1. Nail the r25/GOT-base convention from the psABI and set it appropriately
   (e.g. a per-object GOT base the linker records; if library functions expect
   r25 = their GOT base, we may need trampolines that set r25 before the call).
2. Keep the guest's lazy PLT and emulate the resolver trampoline (PLT[0]),
   letting the guest's own linker logic set up registers — more faithful but
   requires running the interpreter's resolve path.
3. Run the guest's real interpreter (/usr/lib/libc.so.1) as the program's
   entry, letting it do all linking. Most faithful, heaviest.

Static binaries (echo/cat/pwd/ls) are unaffected and continue to work.
