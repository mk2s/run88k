# run88k

**A user-mode syscall emulator for the Motorola 88000 (MC88100) — run real m88k
Unix binaries, and their native toolchains, on a modern Linux, macOS, or Windows
host.**

run88k is `qemu-user` for the 88k. It loads a userland executable built for a
historical m88k operating system, emulates its instructions on the
[`musashi88k`](https://github.com/mk2s/musashi88k) CPU core, and services its
system calls on the host. No ROM, no full-system hardware — just the program and
its syscalls. It was developed for experimenting with native C compilers and toolchains.

It currently implements Motorola SysV, DG/UX, Tektronix UTek, NetBSD and OpenBSD.  For DG/UX, SysV, OpenBSD shared object libraries are supported, for NetBSD and UTek a.out static linked executables only.

```
$ run88k --root /mnt/dgux --mount /usr=/mnt/dguxusr --mount /work=/tmp/work \
         --cwd /work run /mnt/dguxusr/bin/cc -o hello hello.c
$ run88k --root /mnt/dgux --mount /usr=/mnt/dguxusr --cwd /work run /work/hello
hello from m88k cc
```

The above is an example of running 1990s Data General AViiON C compiler to produce a binary called hello, then running the binary.

---

## Highlights

- **Five guest personalities, each recovered from real hardware images:**

  | Personality | OS / Hardware | Format | Trap / num reg | Status |
  |---|---|---|---|---|
  | `sysv88`  | Motorola UNIX System V/88 R4 (MVME187/197) | ELF32-BE | 451 / r9  | Utilities + full `cc` toolchain |
  | `openbsd` | OpenBSD 7.1 luna88k | ELF32-BE | 450 / r13 | Static **and** dynamic binaries (real `ld.so`) |
  | `netbsd`  | NetBSD luna88k (GCC 3.3.6) | ELF32-BE | 128 / r13 | Utilities + `cc`/`make`; partial kernel build |
  | `dgux`    | Data General DG/UX (AViiON) | ELF32-BE | 450+128 / r9 | Dynamic binaries + full `cc` toolchain |
  | `utek`    | Tektronix UTek XD88 | 88K BCS COFF | 450 / r9 | Static utilities including toolchain |

- **Pluggable ABI design.** Each OS is a *personality*: a syscall vector, number
  register, errno map, syscall table, process-startup contract, and executable
  format. Adding a new OS never touches the run loop.

- **Real toolchains, end to end.** `cc -o prog prog.c` driving `cpp`/`cc1`/`as`/
  `ld` to a working binary works on SysV/88, DG/UX, and NetBSD. Multi-TU builds,
  `-O` optimization, `make`, and the libelf tools (`nm`, `size`, `dump`, `ar`)
  all run.

- **Dynamic linking two ways.** Run the guest's own `ld.so` (OpenBSD) or
  self-link NEEDED libraries and apply relocations in-process (SysV/88, DG/UX).

- **Guest filesystem with a mount table.** A chroot-style guest `/` plus
  arbitrary `--mount GUEST=HOST` points, with guest symlink and mount
  resolution — so `bin -> /usr/bin` lands where the guest expects.

- **Process model.** `fork`/`exec`/`wait`/`pipe` on a host-process backend, so a
  guest shell drives builtins, external commands, redirection, and pipelines.

- **Diagnostics first.** `--trace` (strace-style syscall logging), `--trace-all`
  (per-instruction PC/register trace), `--watch ADDR`, a fail-fast fault report,
  and a `--selftest` core-integration check.

---

## Requirements

- **[Zig](https://ziglang.org/download/) 0.17.0** — the current stable release
  (the `build.zig.zon` pins `minimum_zig_version`). See below for install.
- A guest m88k filesystem to run against (see **Getting a guest filesystem**).

### Installing Zig

Zig is a single self-contained binary — no installer, no runtime dependencies.
Download, extract, and put it on your `PATH`:

- **Any OS:** grab the 0.17.0 archive for your platform from
  [ziglang.org/download](https://ziglang.org/download/), extract it, and add the
  extracted directory to your `PATH`.  Or package install...
- **macOS:** `brew install zig`
- **Linux:** your distro may package it (`pacman -S zig`, `snap install zig
  --classic`, etc.); otherwise use the tarball above.
- **Windows:** `winget install zig.zig` or `scoop install zig`, or the zip above.

Verify with `zig version` (should print `0.17.0`). If you juggle multiple Zig
versions, [zvm](https://github.com/tristanisham/zvm) installs and switches
between them (`zvm install 0.17.0 && zvm use 0.17.0`).

The **`musashi88k`** CPU core is a declared dependency in `build.zig.zon` and is
fetched and cached automatically by `zig build` — you do **not** need to clone it
separately.

run88k is pure userland and cross-platform: the same code builds and runs on
Linux, macOS, and Windows.

---

## Building

Clone the repo and build — that's it. The `musashi88k` CPU core is declared in
`build.zig.zon` (pinned to a specific commit for reproducible builds) and is
fetched and cached by `zig build` on first run.

```
git clone https://github.com/mk2s/run88k.git
cd run88k
```

The commands are identical on all three platforms.

### Linux / macOS

```sh
zig build                 # builds zig-out/bin/<arch>-<os>/run88k
zig build test            # run the unit tests
./zig-out/bin/*/run88k --selftest
```

### Windows (PowerShell or cmd)

```powershell
zig build
zig build test
.\zig-out\bin\x86_64-windows\run88k.exe --selftest
```

The build installs per target as `zig-out/bin/<arch>-<os>/run88k` so cross-builds
do not clobber each other. To cross-compile, pass a target triple, e.g.:

```sh
zig build -Dtarget=aarch64-macos      # Apple Silicon from anywhere
zig build -Dtarget=x86_64-windows     # a Windows exe from Linux/macOS
zig build -Doptimize=ReleaseFast      # optimized build (big compiles emulate billions of instructions)
```

To update the pinned CPU core to a newer `musashi88k` commit, point the
dependency at the new archive and refresh its hash:

```sh
zig fetch --save=musashi88k \
  https://github.com/mk2s/musashi88k/archive/<commit-sha>.tar.gz
```

To develop against a local `musashi88k` checkout instead, temporarily set the
dependency to a path in `build.zig.zon`:
`.musashi88k = .{ .path = "../musashi88k" }`.

> **Note for Windows + guest filesystems.** The emulator builds and runs
> natively on Windows, but the easiest way to *mount* a vintage m88k disk image
> is FUSE (see below), which is a Unix facility. On Windows, either mount images
> under WSL and point run88k at the WSL path, or extract an image to a plain
> directory tree and use that as `--root`.

---

## Quick start

A sanity check with no guest filesystem needed:

```sh
run88k --selftest
# selftest: stop=trap last_trap=451 r9=4
# selftest: PASS
```

Run a real static binary (OpenBSD luna88k `/bin/echo`), auto-detecting the
personality from the ELF:

```sh
run88k --root /mnt/obsd run /mnt/obsd/bin/echo hello world
```

Run a DG/UX dynamic binary, resolving its libraries through the guest tree:

```sh
run88k --root /mnt/dgux --mount /usr=/mnt/dguxusr run /mnt/dguxusr/bin/id
```

Compile and run a C program with the guest's own compiler (SysV/88):

```sh
run88k --root /mnt/hd0_root --mount /usr=/mnt/hd0_slice3 \
       --mount /work=/tmp/work --cwd /work \
       run /mnt/hd0_slice3/ccs/bin/cc -o hello hello.c

run88k --root /mnt/hd0_root --mount /usr=/mnt/hd0_slice3 --cwd /work \
       run /work/hello
```

### Command-line reference

```
run88k [flags] run <host-path-to-guest-binary> [guest args...]
run88k --selftest
```

| Flag | Meaning |
|---|---|
| `--root DIR`       | Mount `DIR` as the guest `/`. |
| `--mount G=H`      | Mount host path `H` at guest prefix `G` (repeatable, up to 16). |
| `--cwd DIR`        | Guest-absolute initial working directory (point at a writable mount to compile into). |
| `--os NAME`        | Force a personality: `sysv88`, `openbsd`, `netbsd`, `utek`, `dgux`. Auto-detected from the ELF/COFF when omitted. |
| `--trace`          | strace-style per-syscall logging to stderr. |
| `--trace-all`      | Per-instruction PC/register trace (deep core debugging). |
| `--watch HEX`      | Watch a guest memory address. |
| `--max-steps N`    | Instruction budget (`0` = unlimited; a heavy `-O2` compile can need billions). |
| `--selftest`       | Assemble and run a syscall trap to verify core integration. |

> The run target is given as a **host** path (so run88k can read the file);
> run88k rewrites the guest-visible `argv[0]` to the corresponding guest path
> through the mount table, which the toolchain drivers depend on to find their
> sub-tools.

---

## Getting a guest filesystem (and why FUSE helps)

run88k runs the guest's **own** binaries, libraries, headers, and toolchain — so
you need that OS's filesystem available to the host as a directory tree. Each
personality was brought up against a real disk image from the corresponding
machine.

Vintage m88k systems used filesystems the host does not mount natively (SysV/88
slices, BSD FFS/UFS1, DG/UX's own layout, UTek's UFS).   I've written FUSE fs for the host.

If you're looking for the easiest, linux should be able to mount the OpenBSD snapshot fs founnd here:

---

## Status and scope

What works today is documented per platform under `docs/`:

- `docs/abi-sysv88.md`, `docs/abi-openbsd.md`, `docs/abi-netbsd.md`,
  `docs/abi-dgux.md`, `docs/abi-utek.md` — the recovered ABI for each
  personality (trap vector, number register, errno map, startup contract).
- `docs/toolchain.md` — compiler/assembler/linker bring-up notes per platform.
- `docs/dynamic-linking.md` — the two dynamic-linking strategies.
- `docs/process-model.md` — fork/exec/wait/pipe.

**Out of scope** (matching the user-mode model): ROM / full-system hardware,
supervisor mode / MMU / `rte`, and devices beyond what the CLI workload needs.
The SFU1 **FPU is stubbed** in the core; floating-point-heavy workloads will
force FPU work. Signals are minimally modeled and threads are not yet modeled.

## Related projects

- **[musashi88k](https://github.com/mk2s/musashi88k)** — the MC88100 CPU core
  run88k drives.
- **[att-unixpc-syscall-emulator](https://github.com/mk2s/att-unixpc-syscall-emulator)** — the sibling AT&T UNIX PC (3B1 / MC68010 / COFF / SVR2) syscall emulator
- **[FUSE-utek](https://codefloe.com/mk2s/FUSE-utek)** — a FUSE fs for Utek images.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Maki Kato.
