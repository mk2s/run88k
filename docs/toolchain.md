# Toolchain (as / cc / ld) — status

All three are dynamically-linked ELF (`interpreter /usr/lib/libc.so.1`), the same
class as `date`, and they all load + run their dynamic startup.

## RESOLVED: full `cc` compile works end-to-end

`cc -o hi hi.c` compiles a real C program (cpp -> ccom -> as -> ld) to a valid
`ELF 32-bit MSB executable, Motorola m88k, dynamically linked`, and the result
RUNS under run88k (prints via printf, returns its exit code). Verified:
```
$ cc -o hi hi.c          # hi.c: printf("hello from m88k cc\n"); return 3;
$ run88k ... run hi   ->  hello from m88k cc   (exit 3)
```

Three things had to be in place (all in the syscall layer):
1. **file-backed mmap with MAP_SHARED write-back.** `as` and `ld` build their
   ELF output in a `mmap(fd, MAP_SHARED)` of the output file and rely on
   `munmap` flushing the mapped bytes back to disk. `sysMmap` now `pread`s the
   file into the region on map; MAP_SHARED file maps are tracked (with a dup'd
   fd) and `munmap` `pwrite`s the region back. Without write-back, `as`
   produced a 0-byte `.o` (this was the real cause of the old "as faults on a
   real token" symptom — after earlier fixes it stopped faulting but silently
   wrote nothing).
2. **`--cwd <guest-dir>` flag.** `cc` runs its sub-tools with output paths
   relative to the CWD (e.g. `as` writes `t.o`, not `/work/t.o`). The guest CWD
   defaults to `/` (read-only root), so relative outputs failed with "Cannot
   Open Output File". Run with `--cwd /work` (a writable mount).
3. **New syscalls:** `memcntl (131)` (advisory cache/sync, no-op success),
   `chmod (15)` + `fchmod (93)` (ld sets the output's mode; path-resolved
   through the mount table). Plus `munmap (117)`/`mprotect (116)` from the
   size/nm work.

## Verified cc capabilities
- **`-O` optimization works**: `cc -O -o hi hi.c` produces a correct binary
  (optimizer register allocation, the `optim` pass — all fine).
- **Multi-translation-unit**: `cc -O -c -o a.o a.c`, `cc -O -c -o b.o b.c`,
  `cc -o prog a.o b.o` links and runs correctly.
- Exercised: recursion (fib), `%`/loops (gcd), string.h (strcpy/strcat/strlen),
  nested-loop sort, arrays, exit codes — all correct.
- **Language level is K&R / C89** (1991 CCCS). C99isms fail with real cc
  diagnostics: no `for(int i=...)` init-decls, no mid-block declarations. Use
  old-style function defs and top-of-block declarations.

## KNOWN: `cc` without `-o` faults (PROBABLE latent cc driver bug, NOT an emulator bug)
`cc foo.c` / `cc -c foo.c` / `cc -S foo.c` / `cc -V foo.c` (any invocation with
no explicit `-o`) faults with a NULL deref inside libc `strcmp` (guest pc
0x50341c8 = libc `strcmp` vaddr 0x341c8, `ld.bu r2,r3,r5` with r3=0). Traced
entirely to cc's own `main()` (Ghidra-decompiled, program `cc`):

- In the non-option-argument case (`case 0xffffffff:`, the input filename), cc
  does `derived = setsuf(name, 'o')` (turn `foo.c` -> `foo.o`) then
  `strcmp(derived, uStack_14)` to detect an output==input collision.
- `uStack_14` is main's local at stack slot **fp+0x7c**. It is written ONLY
  inside the `-o` option handler (`case 0x6f:`, cc code at 0x213ac and 0x213ec:
  `st r2,r31,0x7c`). The function prologue never initializes it.
- With no `-o` on the command line, `case 0x6f` never runs, so `uStack_14` is
  read uninitialized. Under run88k the entire guest address space is zero-filled
  at init (`mem.zig` `@memset(buf,0)`), so the slot reads as NULL and libc
  `strcmp(derived, NULL)` dereferences address 0 -> fault.

Every syscall on the path succeeded and the CPU faithfully executed the NULL
deref cc coded. The working `-o` invocations (`cc -o hi hi.c`, `cc -o x -c x.c`)
initialize the same slot to a valid pointer and never fault — confirming the
slot is the trigger.

This is a **probable cc bug** (use of an uninitialized local), masked on real
SysV/88 hardware because the stack slot would hold stale non-NULL garbage from a
prior frame; page 0 is unmapped there too, so a genuinely-NULL slot would fault
on real hardware as well. Our zero-filled stack is arguably *more* deterministic
than the hardware, which is what surfaces the latent bug.

Per decision: **noted as a probable cc bug; no emulator action taken.**
**Workaround: always pass `-o`.** (Mapping/seeding memory to paper over it was
rejected — it would mask genuine null-deref bugs.)

Note on tooling: nothing was wrong with Ghidra's ELF loader here — it loaded
`cc` correctly (image_base 0x20034, proper .text, 259 funcs, retained .symtab)
once a stale raw-binary import of the same name was removed. When multiple
programs are open, pass `program=<name>` explicitly on every Ghidra MCP call;
the default active program is not reliably the one just switched to.

## Requirements to run the toolchain
- Mounts: `--root <hd0_root> --mount /usr=<hd0_slice3>` as usual, PLUS a
  **writable temp** at the guest's temp path (`--mount /var/tmp=/tmp/guest_vartmp`)
  AND a **writable working dir** (`--mount /work=/tmp/asm88`).
- **`--cwd /work`** so sub-tool relative output paths land in the writable dir.
- **Always pass `-o`** (see the no-`-o` cc bug above).

## Syscalls added (surfaced by the toolchain)
- **unlink (10)**, **rename (134)**, **mkdir (80)**, **rmdir (79)**,
  **creat (8)** — path-resolved through the mount table (creat delegates to
  open with O_WRONLY|O_CREAT|O_TRUNC). `as` uses unlink/rename to manage its
  temp relocation file.
- **memcntl (131)**, **chmod (15)**, **fchmod (93)**, **munmap (117)**,
  **mprotect (116)** — see the cc section above.

## RESOLVED: `as` (/usr/ccs/bin/as) — WORKS
Assembles a real `.s` (directives + instructions) to a valid m88k ELF
relocatable. The former "faults / empty .o on a real token" was the
MAP_SHARED-writeback gap, now fixed.

## RESOLVED: the `lda` core bug (was blocking as/dis/cc)

The faults below were all one root cause: the m88k `lda`/`lda.d`/`lda.h`/`lda.b`
(load-address, scaled register-index) instructions were not implemented in the
core (op6 0x0c-0x0f fell into `memRegister`'s `else` and did nothing). `lda` is
the scaled `base + index*size` address-generation op, used everywhere in the
toolchain's table/array indexing. With it a no-op, pointers came out unaligned/
garbage, cascading into absurd malloc sizes (e.g. the infamous `0x50000000` =
`20 * 0x4000000`, where 0x4000000 was an unaligned load off a bad pointer).
Fixed in `musashi88k/src/decode.zig`; see `docs/core-fixes.md` #4.

After the fix:
- **`as`** assembles real m88k instructions (`text`/`global`/`or`/`jmp`) to a
  valid ELF relocatable object.
- **`dis`** produces a full correct disassembly of a real object (crt1.o).
- **`date`** and the static utilities remain unregressed.

## `as` (/usr/ccs/bin/as) — WORKS (was PARTIALLY WORKING)
- **Empty / comment-only / whitespace-only input assembles to a valid m88k ELF
  relocatable object** (verified: `file` reports "ELF 32-bit MSB relocatable,
  Motorola m88k"). So the dynamic loader, libc, file I/O, and ELF object
  emission all work end-to-end.
- **Any input containing a real token (a label, a directive, or an
  instruction) faults**: `as` computes an out-of-bounds index into one of its
  tables and stores/loads past the end of its heap (fault at a ~0x1ffcxxx or
  ~0x4baxxx address).

### Investigation so far (not yet resolved)
The fault traces to `as` reading a packed two-halfword counter word (e.g.
`0x00010002`) with a full-word `ld` and using it as a table index (scaled ×4 in
an `lda`), producing a multi-megabyte offset. Every individual instruction on
the path was replayed through the nono MC88100 oracle and **matched**:
`ld.hu`, `st.b`, `cmp`, `lda`, `mak` all agree. A dedicated unit test confirmed
`st.b` writes the correct big-endian byte offset (an earlier "wrong offset"
reading was a difftrace artifact from reporting an *unaligned* word; difftrace
now masks the reported mem address to the aligned word).

So the divergence, if it is an emulator bug, is upstream of the fault and not
yet localized; alternatively `as` depends on some memory/syscall state we don't
reproduce faithfully. Next step is a broader lockstep diff (bulk-replay a window
of the first-token path against nono) to find the first divergent register
value, the same method that found the `ext`, register-indexed-load, and
`ld.hu`/`ld.bu` core bugs.

## cc (/usr/ccs/bin/cc) — driver runs
`cc` runs its driver and produces real diagnostics (e.g. rejects `-S -o x.s`
with "assembler output does not end in .o"), i.e. option parsing + the fork/exec
of sub-tools is exercised. A full compile currently hits a null-pointer load in
libc downstream (needs the same lockstep treatment, likely the same root cause
as `dis`).

## dis (/usr/ccs/bin/dis) — runs; faults inside a specific libc malloc path
- **Usage message and empty/`.text`-less objects work** (`dis empty.o` prints
  "no data in section .text"). ELF parsing + libc I/O are fine.
- **Disassembling an object with code (e.g. crt1.o) faults**: libc's malloc
  requests `brk(0x50060140)` — i.e. `0x50000000 (libc load bias) + 0x60140
  (the real program break)`. Our brk rejects an address in the library region,
  malloc returns NULL, and `dis` dereferences it (`ld r13,r2,0x8` with r2=0).

### Root cause (partially localized, not yet fixed)
Traced with difftrace+nono into a libc heap/`morecore` routine (unbiased vaddr
~0x33340) that `date` never reaches (`date` uses a simpler malloc path — this is
why `date` works and `dis` doesn't, on the same libc). That routine computes the
heap arena base from a register that holds **0x50000000, the library load bias**,
then adds the program break. Every individual instruction on the path matches
the nono oracle; the 0x50000000 is a *data value* that flows in, not a
miscomputation. So libc's malloc is using the library's mapping base as the heap
origin, which is wrong in our layout (libraries load at 0x5000000+0x800000*n; the
heap should grow from the executable's break).

Notes gathered:
- libc's `_end`/`_edata`/`_etext` are **SHN_ABS** and live only in libc's
  **.symtab, not .dynsym**, so the dynamic linker never sees them; and libc has
  **no named relocation** for them (they're referenced via nameless RELATIVE
  relocs). Break/malloc globals (`_nd`, `curbrk`, `sbrk`, ...) are **not in
  libc's .dynsym** either, so the `_nd` seed in dynamic.zig silently no-ops for
  this libc — libc tracks the break internally and initializes it via an
  `sbrk(0)` query (which our brk services correctly: the first `sbrk(0)`
  returned the right break 0x5a13c, and the first grow `brk(0x5e140)` was
  correct).

### Fix applied this session (correct regardless)
`dynamic.zig` `lookup()` now returns **SHN_ABS** symbol values **without adding
the object bias** (linker-defined absolute markers like `_end` must not be
biased). This did not fix `dis` (libc doesn't reach `_end` via a named lookup),
but it is correct and guards against the ABS-biasing class of bug.

### Next step for dis/cc
The remaining issue is a dynamic-layout / libc-malloc-arena interaction, not a
single-instruction core bug. Likely needs the library/heap layout to match what
libc's `morecore` assumes (heap contiguous above the executable, libraries out
of the way), or targeted correction of the arena-base value libc derives.
Substantial dynamic-linking work rather than a quick patch.
(NOTE: the dis/cc arena issue above was later resolved by the `lda` core fix —
see core-fixes.md #4 — dis now works.)

## nm / size (/usr/ccs/bin) — RESOLVED (work correctly)

`size` and `nm` now produce correct output on real ELF objects:
```
$ size crt1.o           -> 204 + 64 + 0 = 268
$ size dis              -> 80860 + 21392 + 4508 = 106760
$ nm crt1.o             -> full symbol table (Index/Value/Size/Type/Bind/Shndx/Name)
```

### Root cause (three independent gaps, all in the syscall layer)
The tools' libelf reads the object with a **file-backed `mmap`**, then prints
via buffered stdio. Three missing pieces each blocked output:

1. **File-backed `mmap` was unsupported.** `sysMmap` rejected any `mmap` with a
   real fd (returned EINVAL). libelf then fell back to a malloc+read path that
   leaves the cached Ehdr unpopulated, so `elf_getehdr` (the REAL one,
   FUN_000211e0's `bsr 0x23920`) returned NULL and the printer bailed. **Fix:**
   `sysMmap` now honors file-backed `MAP_PRIVATE`: allocate a region and `pread`
   the file bytes (at the requested offset) into it. libelf's ehdr translation
   then reads straight from the mapping.
2. **`munmap` (117) / `mprotect` (116) were unimplemented** -> fault right after
   the file was processed. **Fix:** accept and return success (we don't reclaim
   the range; `mmap_next` only grows downward, which is fine).
3. **`ioctl(TCGETA)` always returned ENOTTY** -> stdout was fully buffered, and
   `size`/`nm` `_exit` without flushing, so the buffered output was discarded.
   **Fix:** `sysIoctl` handles TCGETA/TCSETA by consulting `isatty()` on the
   mapped host fd. On a terminal it reports tty-ness (fills a plausible
   `struct termio`), so stdio line-buffers stdout and each newline is written
   immediately -> output appears. On a pipe/file it still returns ENOTTY
   (block-buffered), matching real behavior.

Note the earlier "FUN_00023868 is elf_getehdr / +0x6c cache" theory was a
misidentification: 0x23868 is an archive-member getter (`elf_getarhdr`-like);
the real `elf_getehdr` is `bsr 0x23920` inside the printer FUN_000211e0, and it
succeeds once the file is mmap'd. handle+0x6c (written only by the kind==1
archive-member parser) is legitimately 0 for a plain ELF and is not the issue.

### Verified working after the fix (whole libelf inspection family)
- `size` -> `204 + 64 + 0 = 268`
- `nm` -> full symbol table
- `dump -fh` -> ELF header + section header table
- `mcs -p` -> comment/version section
- `ar t <lib.a>` -> archive member listing (exercises the kind==1 archive path
  end-to-end)
- `m4` -> `define(x,hi)x` yields `hi`. The docs previously filed m4's no-output
  as a separate temp-file/diversion issue; it was the SAME stdout-buffering
  problem and the ioctl line-buffering fix resolved it too.

### Verified unregressed
`dis`, `date`, `echo`, `ld -V`, static utilities, single `sh -c` commands;
`zig build test` green; musashi `zig build difftest` 39/39.

Note: `lorder` is a `/bin/sh` script (not ELF), so `run88k run <hostpath>`
rejects it with "NotElf" — invoke it through the guest shell instead.

--- historical notes (pre-fix) below ---

Both run, link, parse options (getopt/optind correct), and hit the error path
cleanly (`size /nonexistent` prints "cannot open"). On a VALID ELF they read the
file but print nothing.

### Fix applied: uname(2) return value (mmap availability probe)
libelf's `_elf_inline`/mmap-availability probe (FUN_00026198) calls `uname(2)`
and treats a return `> 0` as "mmap available", `<= 0` as "use malloc+read".
Our `uname` returned 0 (Linux convention); **SysV/88 `uname(2)` returns a
positive value (1)** on success. Fixed `sysUname` to return 1. This moved
size/nm onto the mmap code path (matching what `dis` does), which is the correct
behavior — verified dis/date/sh/echo unregressed.

### Scope: shared across the libelf inspection tools
A ccs survey shows the no-output issue is a **single shared libelf root cause**,
not per-tool:
- **No output on a valid ELF (crt1.o):** `size`, `nm`, `dump`, `mcs` — all the
  tools that read section/symbol data via `elf_getehdr` + section access.
- **Works:** `dis` (uses a different/lower-level libelf path), `ld -V` (version
  banner). Usage/option-error messages print fine for ALL tools (dump, nm, ar,
  yacc, lex, strip) — so stdout/stderr and early output work; the failure is
  specifically in the libelf ehdr/section-read path.
- **Separate issue:** `m4` (not libelf) also produces no output — it routes all
  output through temp-file "diversions" (`/tmp/m4aXXXXX`) and the diversion
  write/read-back path yields nothing; distinct from the libelf family, tracked
  separately.

Fixing the one libelf ehdr-cache bug should light up size/nm/dump/mcs together.

### Still open: ELF-header cache never populated
After the mmap fix, `size`'s libelf still fails at `elf_getehdr` (FUN_00023868):
it reads the Elf handle's cached ehdr pointer at offset +0x6c, finds it 0, sets
error 0x501, and returns NULL -> "invalid file type" -> no output. The parser
that would set +0x6c (FUN_00021d28) is never reached: `elf_begin`'s recognition
sets the handle's kind (+0x4c) to 3 (ELF_K_ELF), and the parser is gated on
kind==1. The gate `cmp(kind,1)` / `bb0 #3` was verified to behave correctly
(kind=3 legitimately skips the kind==1 path). So the ehdr must get parsed by a
path we're not triggering — not yet localized to a single divergent instruction.
This differs from `dis`, which uses libelf's low-level section walk and works.
Deferred.
