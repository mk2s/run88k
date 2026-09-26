//! 88K BCS (Binary Compatibility Standard) COFF executable loader.
//!
//! This is the Tektronix UTek XD88 executable format (and the 88open BCS COFF
//! more generally). Layout, verified against real UTek binaries
//! (~/Documents/FUSE-utek/tekroot/bin/{echo,cat,ls,pwd}) — see docs/abi-utek.md:
//!
//!   File header (20 bytes, big-endian):
//!     f_magic  u16 @0   == 0x016d  (MC88000 COFF magic; `file` says "88K BCS")
//!     f_nscns  u16 @2   number of section headers
//!     f_timdat u32 @4
//!     f_symptr u32 @8   symbol table file offset (0 if stripped)
//!     f_nsyms  u32 @12
//!     f_opthdr u16 @16  size of the optional (a.out) header
//!     f_flags  u16 @18
//!
//!   Optional a.out header (f_opthdr bytes, typically 28, big-endian):
//!     magic    u16 @0   == 0x010b
//!     vstamp   u16 @2
//!     tsize    u32 @4   text size
//!     dsize    u32 @8   initialized data size
//!     bsize    u32 @12  bss size
//!     entry    u32 @16  entry point (virtual address)
//!     text_start u32 @20
//!     data_start u32 @24
//!
//!   Section headers start at 20 + f_opthdr. **STRIDE IS 44 BYTES**, not the
//!   textbook COFF 40: the m88k variant pads the header (same alignment
//!   padding seen in `struct syment`'s n_pad1/n_pad2). Fields:
//!     s_name    [8] @0    ".text" / ".data" / ".bss" / ".comment"
//!     s_paddr   u32 @8
//!     s_vaddr   u32 @12   load address
//!     s_size    u32 @16   size in bytes
//!     s_scnptr  u32 @20   file offset of the section's raw data (0 for .bss)
//!     s_relptr  u32 @24
//!     s_lnnoptr u32 @28
//!     s_nreloc  u16 @32
//!     s_nlnno   u16 @34
//!     s_flags   u32 @36
//!     (4 bytes pad @40 -> next header at +44)
//!
//! We classify loadable sections by NAME (the s_flags STYP_* bits are 0 in
//! these fully-linked binaries): `.text` and `.data` are copied from the file
//! at s_scnptr into guest memory at s_vaddr; `.bss` is zero-filled at s_vaddr
//! (s_scnptr is 0); `.comment` and anything with vaddr 0 is non-loadable and
//! skipped. These executables are statically linked (no relocation needed).

const std = @import("std");
const mem = @import("../mem.zig");

pub const Error = error{
    NotCoff,
    NotM88k,
    BadHeader,
    BadSections,
    LoadOutOfRange,
};

pub const LoadedImage = struct {
    entry: u32,
    /// Initial program break: end of the highest loaded section (unrounded).
    brk: u32,
    load_low: u32,
    load_high: u32,
};

pub const F_MAGIC_M88K: u16 = 0x016d; // "88K BCS" (UTek, SDE as/ld output)
pub const F_MAGIC_M88K_GCC: u16 = 0x0161; // older AT&T m88k COFF (DG/UX GCC 2.x
// toolchain: gcc/gcc-cpp/gcc-cc1). Same 44-byte scnhdr / a.out-header layout.
pub const AOUT_MAGIC: u16 = 0x010b;

/// True if `magic` is one of the m88k COFF file magics we load.
fn isM88kCoffMagic(magic: u16) bool {
    return magic == F_MAGIC_M88K or magic == F_MAGIC_M88K_GCC;
}
const FILHDR_SIZE: usize = 20;
const SCNHDR_STRIDE: usize = 44;

fn rd16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .big);
}
fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .big);
}

/// True if `image` looks like an 88K BCS COFF object (magic 0x016d). This is
/// the auto-detect hook used to select the UTek personality when the CLI
/// didn't force one.
pub fn detect(image: []const u8) bool {
    return image.len >= 2 and isM88kCoffMagic(rd16(image, 0));
}

/// Validate the file header for an m88k BCS COFF executable.
pub fn checkHeader(image: []const u8) Error!void {
    if (image.len < FILHDR_SIZE) return error.NotCoff;
    if (!isM88kCoffMagic(rd16(image, 0))) return error.NotM88k;
}

/// Load `image` (raw file bytes) into `memory`. Permission enforcement is
/// disabled while writing and restored on return.
pub fn load(memory: *mem.Memory, image: []const u8) Error!LoadedImage {
    try checkHeader(image);

    const f_nscns = rd16(image, 2);
    const f_opthdr = rd16(image, 16);
    if (f_nscns == 0) return error.BadSections;

    // Entry point: prefer the optional-header entry when present, else the
    // .text virtual address (found while walking sections).
    var entry: u32 = 0;
    var have_entry = false;
    if (f_opthdr >= 20) {
        if (FILHDR_SIZE + f_opthdr > image.len) return error.BadHeader;
        // (magic at +0 is 0x010b; we don't require it strictly)
        entry = rd32(image, FILHDR_SIZE + 16);
        have_entry = true;
    }

    const sh_base = FILHDR_SIZE + f_opthdr;

    const was_enforce = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was_enforce;

    var load_low: u32 = 0xffff_ffff;
    var load_high: u32 = 0;
    var text_vaddr: u32 = 0;
    var mapped_any = false;

    var i: usize = 0;
    while (i < f_nscns) : (i += 1) {
        const sh = sh_base + i * SCNHDR_STRIDE;
        if (sh + 40 > image.len) return error.BadSections;

        const name_raw = image[sh .. sh + 8];
        const name = std.mem.sliceTo(name_raw, 0);
        const s_vaddr = rd32(image, sh + 12);
        const s_size = rd32(image, sh + 16);
        const s_scnptr = rd32(image, sh + 20);

        const is_text = std.mem.eql(u8, name, ".text");
        const is_data = std.mem.eql(u8, name, ".data");
        const is_bss = std.mem.eql(u8, name, ".bss");

        // Skip non-loadable sections (.comment, .lib, debug) and any section
        // with no virtual address.
        if (!is_text and !is_data and !is_bss) continue;
        if (s_vaddr == 0 or s_size == 0) continue;

        const seg_end = s_vaddr +% s_size;
        if (seg_end < s_vaddr or seg_end > mem.Memory.size) return error.LoadOutOfRange;

        if (is_bss) {
            // Uninitialized data: zero-fill; no file bytes (s_scnptr is 0).
            memory.zero(s_vaddr, s_size);
            memory.addRegion(s_vaddr, s_size, .{ .read = true, .write = true }) catch return error.LoadOutOfRange;
        } else {
            // .text / .data: copy the raw bytes from the file.
            if (s_scnptr == 0 or @as(u64, s_scnptr) + s_size > image.len) return error.BadSections;
            memory.writeBytes(s_vaddr, image[s_scnptr .. s_scnptr + s_size]);
            memory.addRegion(s_vaddr, s_size, .{
                .read = true,
                // Map text writable too — we don't enforce W^X for the guest,
                // and keeping it simple matches the ELF loader's choice.
                .write = true,
                .exec = is_text,
            }) catch return error.LoadOutOfRange;
            if (is_text and !have_entry) text_vaddr = s_vaddr;
        }

        mapped_any = true;
        if (s_vaddr < load_low) load_low = s_vaddr;
        if (seg_end > load_high) load_high = seg_end;
    }

    if (!mapped_any or load_high == 0) return error.BadSections;
    if (!have_entry) entry = text_vaddr;

    // Initial program break = the EXACT end of the highest loaded section, NOT
    // rounded. The guest's crt/libc computes its first break as the linker's
    // `_end` (== the exact bss end) and grows the heap from there; rounding up
    // leaves an unmapped gap between bss-end and the heap that the guest writes
    // into (verified: /bin/pwd calls brk(bss_end) then faults on the gap).
    return .{
        .entry = entry,
        .brk = load_high,
        .load_low = load_low,
        .load_high = load_high,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a minimal 88K BCS COFF executable with a .text and a .bss section,
/// for testing the parser without a real binary.
fn buildTinyCoff(alloc: std.mem.Allocator, text_vaddr: u32, entry: u32, code: []const u8, bss_vaddr: u32, bss_size: u32) ![]u8 {
    const opthdr = 28;
    const sh_base = FILHDR_SIZE + opthdr;
    const nscns = 2;
    const dataoff = sh_base + nscns * SCNHDR_STRIDE;
    var buf = try alloc.alloc(u8, dataoff + code.len);
    @memset(buf, 0);
    // file header
    std.mem.writeInt(u16, buf[0..2], F_MAGIC_M88K, .big);
    std.mem.writeInt(u16, buf[2..4], nscns, .big);
    std.mem.writeInt(u16, buf[16..18], opthdr, .big);
    // optional a.out header
    std.mem.writeInt(u16, buf[FILHDR_SIZE + 0 ..][0..2], AOUT_MAGIC, .big);
    std.mem.writeInt(u32, buf[FILHDR_SIZE + 16 ..][0..4], entry, .big);
    // section header 0: .text
    var sh = sh_base;
    @memcpy(buf[sh .. sh + 5], ".text");
    std.mem.writeInt(u32, buf[sh + 12 ..][0..4], text_vaddr, .big); // s_vaddr
    std.mem.writeInt(u32, buf[sh + 16 ..][0..4], @intCast(code.len), .big); // s_size
    std.mem.writeInt(u32, buf[sh + 20 ..][0..4], @intCast(dataoff), .big); // s_scnptr
    // section header 1: .bss
    sh = sh_base + SCNHDR_STRIDE;
    @memcpy(buf[sh .. sh + 4], ".bss");
    std.mem.writeInt(u32, buf[sh + 12 ..][0..4], bss_vaddr, .big); // s_vaddr
    std.mem.writeInt(u32, buf[sh + 16 ..][0..4], bss_size, .big); // s_size
    std.mem.writeInt(u32, buf[sh + 20 ..][0..4], 0, .big); // s_scnptr = 0
    @memcpy(buf[dataoff..], code);
    return buf;
}

test "loads a minimal 88K BCS COFF executable" {
    const alloc = std.testing.allocator;
    const code = [_]u8{ 0x61, 0x20, 0x00, 0x44, 0xf0, 0x00, 0xd1, 0xc2 }; // or r9,r0,68; tb0 0,r0,450
    const img_bytes = try buildTinyCoff(alloc, 0x2200, 0x2200, &code, 0x402350, 0x1000);
    defer alloc.free(img_bytes);

    var memory = try mem.Memory.init(alloc);
    defer memory.deinit();
    defer mem.setActive(null);

    const img = try load(&memory, img_bytes);
    try std.testing.expectEqual(@as(u32, 0x2200), img.entry);
    // Code landed big-endian at the text vaddr.
    try std.testing.expectEqual(@as(u32, 0x612000_44), memory.read32(0x2200));
    try std.testing.expectEqual(@as(u32, 0xf000d1c2), memory.read32(0x2204));
    // bss end is the high-water mark; brk is that rounded up.
    try std.testing.expectEqual(@as(u32, 0x403350), img.load_high);
    try std.testing.expect(img.brk >= img.load_high);
}

test "detect recognizes the BCS magic and rejects others" {
    try std.testing.expect(detect(&[_]u8{ 0x01, 0x6d, 0, 0 }));
    try std.testing.expect(!detect(&[_]u8{ 0x7f, 'E', 'L', 'F' }));
    try std.testing.expect(!detect(&[_]u8{0x01}));
}
