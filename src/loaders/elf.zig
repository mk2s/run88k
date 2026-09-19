//! ELF32 big-endian (MC88000) executable loader.
//!
//! Parses a static ELF EXEC, maps each PT_LOAD segment into guest memory with
//! its permissions, zero-fills the bss tail (memsz > filesz), and reports the
//! entry point and the initial program break (highest loaded byte, page
//! rounded). This is the SysV/88 lead-platform format: ELF32-BE, statically
//! linked, e_machine = EM_88K (145).

const std = @import("std");
const mem = @import("../mem.zig");

pub const Error = error{
    NotElf,
    NotElf32,
    NotBigEndian,
    NotExecutable,
    NotM88k,
    BadProgramHeaders,
    LoadOutOfRange,
};

pub const LoadedImage = struct {
    entry: u32,
    /// Initial program break: end of the highest PT_LOAD, page-rounded up.
    brk: u32,
    /// Lowest and highest mapped guest addresses (for diagnostics).
    load_low: u32,
    load_high: u32,
};

const EI_NIDENT = 16;
const ELFCLASS32 = 1;
const ELFDATA2MSB = 2; // big-endian
const ET_EXEC = 2;
const EM_88K = 5; // EM_88K in the ELF machine enum (Motorola 88000)
const PT_LOAD = 1;
const PF_X = 1;
const PF_W = 2;
const PF_R = 4;
const PAGE = 0x1000;

fn rd16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .big);
}
fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .big);
}

/// Load `image` (raw file bytes) into `memory`. Permission enforcement is
/// disabled while writing and restored by the caller/run setup.
pub fn load(memory: *mem.Memory, image: []const u8) Error!LoadedImage {
    if (image.len < EI_NIDENT + 36) return error.NotElf;
    if (!std.mem.eql(u8, image[0..4], "\x7fELF")) return error.NotElf;
    if (image[4] != ELFCLASS32) return error.NotElf32;
    if (image[5] != ELFDATA2MSB) return error.NotBigEndian;

    const e_type = rd16(image, 16);
    const e_machine = rd16(image, 18);
    const e_entry = rd32(image, 24);
    const e_phoff = rd32(image, 28);
    const e_phentsize = rd16(image, 42);
    const e_phnum = rd16(image, 44);

    if (e_type != ET_EXEC) return error.NotExecutable;
    if (e_machine != EM_88K) return error.NotM88k;
    if (e_phnum == 0 or e_phentsize < 32) return error.BadProgramHeaders;

    const was_enforce = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was_enforce;

    var load_low: u32 = 0xffff_ffff;
    var load_high: u32 = 0;

    var i: usize = 0;
    while (i < e_phnum) : (i += 1) {
        const ph = e_phoff + i * e_phentsize;
        if (ph + 32 > image.len) return error.BadProgramHeaders;

        const p_type = rd32(image, ph + 0);
        if (p_type != PT_LOAD) continue;

        const p_offset = rd32(image, ph + 4);
        const p_vaddr = rd32(image, ph + 8);
        const p_filesz = rd32(image, ph + 16);
        const p_memsz = rd32(image, ph + 20);
        const p_flags = rd32(image, ph + 24);

        // Range checks against guest memory and the source image.
        const seg_end = p_vaddr +% p_memsz;
        if (seg_end < p_vaddr or seg_end > mem.Memory.size) return error.LoadOutOfRange;
        if (p_filesz > p_memsz) return error.BadProgramHeaders;
        if (@as(u64, p_offset) + p_filesz > image.len) return error.BadProgramHeaders;

        // Copy file-backed bytes, then zero the bss tail.
        if (p_filesz > 0) {
            memory.writeBytes(p_vaddr, image[p_offset .. p_offset + p_filesz]);
        }
        if (p_memsz > p_filesz) {
            memory.zero(p_vaddr + p_filesz, p_memsz - p_filesz);
        }

        // Permission region for this segment.
        memory.addRegion(p_vaddr, p_memsz, .{
            .read = (p_flags & PF_R) != 0,
            .write = (p_flags & PF_W) != 0,
            .exec = (p_flags & PF_X) != 0,
        }) catch return error.LoadOutOfRange;

        if (p_vaddr < load_low) load_low = p_vaddr;
        if (seg_end > load_high) load_high = seg_end;
    }

    if (load_high == 0) return error.BadProgramHeaders;

    // The initial program break is the EXACT end of the highest loaded segment,
    // NOT page-rounded: the guest's crt/libc treats that address as the initial
    // break and grows the heap from there via brk(). Page-rounding would leave
    // the gap [load_high, rounded) unmapped, and the guest writes into it.
    return .{
        .entry = e_entry,
        .brk = load_high,
        .load_low = load_low,
        .load_high = load_high,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a minimal ELF32-BE m88k executable with one R-E PT_LOAD segment
/// carrying `code` at vaddr, for testing the parser without a real binary.
fn buildTinyElf(alloc: std.mem.Allocator, vaddr: u32, entry: u32, code: []const u8) ![]u8 {
    const ehsize = 52;
    const phentsize = 32;
    const phoff = ehsize;
    const dataoff = phoff + phentsize;
    var buf = try alloc.alloc(u8, dataoff + code.len);
    @memset(buf, 0);
    // e_ident
    @memcpy(buf[0..4], "\x7fELF");
    buf[4] = ELFCLASS32;
    buf[5] = ELFDATA2MSB;
    buf[6] = 1;
    std.mem.writeInt(u16, buf[16..18], ET_EXEC, .big); // e_type
    std.mem.writeInt(u16, buf[18..20], EM_88K, .big); // e_machine
    std.mem.writeInt(u32, buf[20..24], 1, .big); // e_version
    std.mem.writeInt(u32, buf[24..28], entry, .big); // e_entry
    std.mem.writeInt(u32, buf[28..32], phoff, .big); // e_phoff
    std.mem.writeInt(u16, buf[40..42], ehsize, .big); // e_ehsize
    std.mem.writeInt(u16, buf[42..44], phentsize, .big); // e_phentsize
    std.mem.writeInt(u16, buf[44..46], 1, .big); // e_phnum
    // program header
    std.mem.writeInt(u32, buf[phoff + 0 ..][0..4], PT_LOAD, .big);
    std.mem.writeInt(u32, buf[phoff + 4 ..][0..4], dataoff, .big); // p_offset
    std.mem.writeInt(u32, buf[phoff + 8 ..][0..4], vaddr, .big); // p_vaddr
    std.mem.writeInt(u32, buf[phoff + 16 ..][0..4], @intCast(code.len), .big); // p_filesz
    std.mem.writeInt(u32, buf[phoff + 20 ..][0..4], @intCast(code.len), .big); // p_memsz
    std.mem.writeInt(u32, buf[phoff + 24 ..][0..4], PF_R | PF_X, .big); // p_flags
    @memcpy(buf[dataoff..], code);
    return buf;
}

test "loads a minimal ELF32-BE m88k executable" {
    const alloc = std.testing.allocator;
    const code = [_]u8{ 0x61, 0x20, 0x00, 0x04, 0xf0, 0x00, 0xd1, 0xc3 };
    const elf = try buildTinyElf(alloc, 0x10000, 0x10000, &code);
    defer alloc.free(elf);

    var memory = try mem.Memory.init(alloc);
    defer memory.deinit();

    const img = try load(&memory, elf);
    try std.testing.expectEqual(@as(u32, 0x10000), img.entry);
    try std.testing.expectEqual(@as(u32, 0x10008), img.brk); // exact end, unrounded
    // Code landed in guest memory big-endian.
    try std.testing.expectEqual(@as(u32, 0x612000_04), memory.read32(0x10000));
    try std.testing.expectEqual(@as(u32, 0xf000d1c3), memory.read32(0x10004));
}

test "rejects little-endian and non-m88k" {
    const alloc = std.testing.allocator;
    const code = [_]u8{ 0, 0, 0, 0 };
    var elf = try buildTinyElf(alloc, 0x10000, 0x10000, &code);
    defer alloc.free(elf);
    var memory = try mem.Memory.init(alloc);
    defer memory.deinit();

    elf[5] = 1; // ELFDATA2LSB
    try std.testing.expectError(error.NotBigEndian, load(&memory, elf));
    elf[5] = ELFDATA2MSB;
    std.mem.writeInt(u16, elf[18..20], 3, .big); // e_machine = EM_386
    try std.testing.expectError(error.NotM88k, load(&memory, elf));
}
