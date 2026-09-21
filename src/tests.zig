//! Test aggregator. Rooted at src/ so every module's relative imports
//! (loaders/, abi/, syscalls/) resolve. `zig build test` runs this.

const std = @import("std");

test {
    _ = @import("mem.zig");
    _ = @import("machine.zig");
    _ = @import("process.zig");
    _ = @import("loaders/elf.zig");
    _ = @import("abi/sysv88.zig");
    _ = @import("abi/openbsd.zig");
    _ = @import("syscalls/dispatch.zig");
    _ = @import("syscalls/dispatch_openbsd.zig");
    _ = @import("syscalls/table_sysv88.zig");
    _ = @import("syscalls/table_openbsd.zig");
    _ = @import("difftrace.zig");
    _ = @import("fs.zig");
    _ = @import("loaders/dynamic.zig");
    _ = @import("procmodel.zig");
}
