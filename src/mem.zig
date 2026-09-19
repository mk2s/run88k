//! Guest address space model for the m88k user-mode emulator.
//!
//! A flat, big-endian backing store with coarse permission regions. The
//! MC88100 is big-endian, so multi-byte accesses assemble/disassemble in
//! big-endian order. An out-of-range or permission-violating access records a
//! sticky fault that the run loop turns into a fail-fast diagnostic.
//!
//! Bridging to the CPU core: musashi88k's `cpu.MemoryBus` is a struct of six
//! C-callconv function pointers that carry no user-data argument. So, exactly
//! as runupc does for Musashi, we route them through a module-global `active`
//! pointer set by the run loop. `bus()` returns a MemoryBus wired to those
//! trampolines.

const std = @import("std");
const m88k = @import("m88k");

pub const Perm = packed struct {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
};

pub const FaultKind = enum { none, unmapped, no_read, no_write, no_exec };

pub const Fault = struct {
    kind: FaultKind = .none,
    address: u32 = 0,
    /// PC at time of fault, filled by the run loop if known.
    pc: u32 = 0,
};

/// A contiguous permission region [start, start+len).
pub const Region = struct {
    start: u32,
    len: u32,
    perm: Perm,

    fn contains(self: Region, addr: u32) bool {
        return addr >= self.start and addr < self.start +% self.len;
    }
};

pub const Memory = struct {
    /// Backing store sized to cover the whole guest range [0, size).
    bytes: []u8,
    /// Permission regions (checked in order; first match wins).
    regions: std.ArrayListUnmanaged(Region) = .empty,
    allocator: std.mem.Allocator,
    /// Last fault recorded (sticky until cleared by the run loop).
    fault: Fault = .{},
    /// When true, permission checks are enforced. Disabled during loading.
    enforce: bool = false,

    /// Total addressable size. 256 MiB covers a generous static layout
    /// (text/data/bss near 0x00010000, heap, and a high stack) without a
    /// sparse/paged scheme. Revisit if a target needs more.
    pub const size: u32 = 0x1000_0000;

    pub fn init(allocator: std.mem.Allocator) !Memory {
        const buf = try allocator.alloc(u8, size);
        @memset(buf, 0);
        return Memory{ .bytes = buf, .allocator = allocator };
    }

    pub fn deinit(self: *Memory) void {
        self.regions.deinit(self.allocator);
        self.allocator.free(self.bytes);
    }

    pub fn addRegion(self: *Memory, start: u32, len: u32, perm: Perm) !void {
        try self.regions.append(self.allocator, .{ .start = start, .len = len, .perm = perm });
    }

    pub fn clearRegions(self: *Memory) void {
        self.regions.clearRetainingCapacity();
    }

    pub fn clearFault(self: *Memory) void {
        self.fault = .{};
    }

    fn permFor(self: *const Memory, addr: u32) ?Perm {
        for (self.regions.items) |r| {
            if (r.contains(addr)) return r.perm;
        }
        return null;
    }

    fn recordFault(self: *Memory, kind: FaultKind, addr: u32) void {
        if (self.fault.kind == .none) {
            self.fault = .{ .kind = kind, .address = addr };
        }
    }

    /// Check an access of `n` bytes at `addr` for the given permission.
    /// Returns false and records a fault on violation.
    fn checkAccess(self: *Memory, addr: u32, n: u32, comptime want: enum { read, write, exec }) bool {
        if (addr > size or n > size or addr +% n > size) {
            self.recordFault(.unmapped, addr);
            return false;
        }
        if (!self.enforce) return true;
        const p = self.permFor(addr) orelse {
            self.recordFault(.unmapped, addr);
            return false;
        };
        switch (want) {
            .read => if (!p.read) {
                self.recordFault(.no_read, addr);
                return false;
            },
            .write => if (!p.write) {
                self.recordFault(.no_write, addr);
                return false;
            },
            .exec => if (!p.exec) {
                self.recordFault(.no_exec, addr);
                return false;
            },
        }
        return true;
    }

    // -- Big-endian typed access (guest is big-endian) ----------------------

    pub fn read8(self: *Memory, addr: u32) u8 {
        if (!self.checkAccess(addr, 1, .read)) return 0;
        return self.bytes[addr];
    }
    pub fn read16(self: *Memory, addr: u32) u16 {
        if (!self.checkAccess(addr, 2, .read)) return 0;
        return std.mem.readInt(u16, self.bytes[addr..][0..2], .big);
    }
    pub fn read32(self: *Memory, addr: u32) u32 {
        if (!self.checkAccess(addr, 4, .read)) return 0;
        return std.mem.readInt(u32, self.bytes[addr..][0..4], .big);
    }

    pub fn write8(self: *Memory, addr: u32, value: u8) void {
        if (!self.checkAccess(addr, 1, .write)) return;
        self.bytes[addr] = value;
    }
    pub fn write16(self: *Memory, addr: u32, value: u16) void {
        if (!self.checkAccess(addr, 2, .write)) return;
        std.mem.writeInt(u16, self.bytes[addr..][0..2], value, .big);
    }
    pub fn write32(self: *Memory, addr: u32, value: u32) void {
        if (!self.checkAccess(addr, 4, .write)) return;
        std.mem.writeInt(u32, self.bytes[addr..][0..4], value, .big);
    }

    // -- Bulk helpers (used by the loader / stack setup) --------------------

    /// Copy host bytes into guest memory, bypassing permission enforcement.
    /// Range-checked.
    pub fn writeBytes(self: *Memory, addr: u32, src: []const u8) void {
        const end = addr +% @as(u32, @intCast(src.len));
        if (end > size or end < addr) {
            self.recordFault(.unmapped, addr);
            return;
        }
        @memcpy(self.bytes[addr..end], src);
    }

    /// Read a NUL-terminated guest C string into the caller-provided buffer.
    /// Returns the string (without NUL).
    pub fn readCStr(self: *Memory, addr: u32, buf: []u8) []const u8 {
        var i: u32 = 0;
        while (i < buf.len) : (i += 1) {
            const a = addr + i;
            if (a >= size) break;
            const ch = self.bytes[a];
            if (ch == 0) break;
            buf[i] = ch;
        }
        return buf[0..i];
    }

    pub fn zero(self: *Memory, addr: u32, len: u32) void {
        const end = addr +% len;
        if (end > size or end < addr) {
            self.recordFault(.unmapped, addr);
            return;
        }
        @memset(self.bytes[addr..end], 0);
    }

    /// A `cpu.MemoryBus` wired to this Memory via the module-global `active`
    /// pointer. Set `active` (setActive) before running so the trampolines
    /// resolve. The core's fn pointers carry no user arg, hence the global.
    pub fn bus(self: *Memory) m88k.MemoryBus {
        setActive(self);
        return .{
            .read8 = &busRead8,
            .read16 = &busRead16,
            .read32 = &busRead32,
            .write8 = &busWrite8,
            .write16 = &busWrite16,
            .write32 = &busWrite32,
        };
    }
};

// ---------------------------------------------------------------------------
// Global active instance + core memory-bus trampolines.
//
// musashi88k's MemoryBus fn pointers have no user-data argument, so route them
// through a module-global pointer set by the run loop (the same pattern runupc
// uses for Musashi's global callbacks).
// ---------------------------------------------------------------------------

pub var active: ?*Memory = null;

pub fn setActive(m: ?*Memory) void {
    active = m;
}

fn busRead8(addr: u32) callconv(.c) u32 {
    const m = active orelse return 0;
    return m.read8(addr);
}
fn busRead16(addr: u32) callconv(.c) u32 {
    const m = active orelse return 0;
    return m.read16(addr);
}
fn busRead32(addr: u32) callconv(.c) u32 {
    const m = active orelse return 0;
    return m.read32(addr);
}
fn busWrite8(addr: u32, value: u32) callconv(.c) void {
    const m = active orelse return;
    m.write8(addr, @truncate(value));
}
fn busWrite16(addr: u32, value: u32) callconv(.c) void {
    const m = active orelse return;
    m.write16(addr, @truncate(value));
}
fn busWrite32(addr: u32, value: u32) callconv(.c) void {
    const m = active orelse return;
    m.write32(addr, value);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "big-endian round trips" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    m.enforce = false;

    m.write32(0x1000, 0x11223344);
    try std.testing.expectEqual(@as(u8, 0x11), m.read8(0x1000));
    try std.testing.expectEqual(@as(u8, 0x22), m.read8(0x1001));
    try std.testing.expectEqual(@as(u8, 0x33), m.read8(0x1002));
    try std.testing.expectEqual(@as(u8, 0x44), m.read8(0x1003));
    try std.testing.expectEqual(@as(u16, 0x1122), m.read16(0x1000));
    try std.testing.expectEqual(@as(u32, 0x11223344), m.read32(0x1000));
}

test "permission enforcement records faults" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    try m.addRegion(0x80000, 0x1000, .{ .read = true, .exec = true });
    try m.addRegion(0x90000, 0x1000, .{ .read = true, .write = true });
    m.enforce = true;

    m.clearFault();
    m.write8(0x80000, 0x42); // write to r-x => fault
    try std.testing.expectEqual(FaultKind.no_write, m.fault.kind);

    m.clearFault();
    m.write8(0x90000, 0x42); // write to rw => ok
    try std.testing.expectEqual(FaultKind.none, m.fault.kind);
    try std.testing.expectEqual(@as(u8, 0x42), m.read8(0x90000));

    m.clearFault();
    _ = m.read8(0x200000); // unmapped => fault
    try std.testing.expectEqual(FaultKind.unmapped, m.fault.kind);
}

test "readCStr" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    m.enforce = false;
    m.writeBytes(0x2000, "hello\x00world");
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("hello", m.readCStr(0x2000, &buf));
}
