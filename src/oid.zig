const std = @import("std");

pub const Scalar = struct {
    oid: []const u8,
    index: u32 = 0,
    kind: u8,
};

pub const Vector = struct {
    oid: []const u8,
    kind: u8,

    // Note: one-indexed and not bounds checked.
    pub fn at(self: Vector, index: u32) Scalar {
        return .{.oid = self.oid, .index = index, .kind = self.kind};
    }
};

pub fn scalar(o: []const u8, kind: u8) Scalar {
    return .{.oid = o, .kind = kind};
}

pub fn vector(o: []const u8, kind: u8) Vector {
    return .{.oid = o, .kind = kind};
}

pub const Date = struct {
    year: u16,
    month: u4,
    day: u5, // 1-indexed
    hour: u5,
    min: u6,
    sec: u6, // 0-60, may include leap seconds
    dsec: u4,

    pub fn parse(str: []const u8) !Date {
        if (str.len != 8 * 2 + 1 or str[0] != '$') return error.InvalidTimestamp;

        return Date{
            .year = try std.fmt.parseInt(u16, str[1..5], 16),
            .month = try std.fmt.parseInt(u4, str[5..7], 16),
            .day = try std.fmt.parseInt(u5, str[7..9], 16),
            .hour = try std.fmt.parseInt(u5, str[9..11], 16),
            .min = try std.fmt.parseInt(u6, str[11..13], 16),
            .sec = try std.fmt.parseInt(u6, str[13..15], 16),
            .dsec = try std.fmt.parseInt(u4, str[15..17], 16),
        };
    }

    pub fn format(
        self: Date,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{}-{}-{} {}:{}:{}.{}", .{
            self.year,
            self.month,
            self.day,
            self.hour,
            self.min,
            self.sec,
            self.dsec,
        });
    }
};

pub const Duration = struct {
    pub const ticks_per_s = 100;

    // In hundreds of a second
    ticks: u64,

    pub fn parse(str: []const u8) !Duration {
        return Duration{
            .ticks = try std.fmt.parseInt(u64, str, 10),
        };
    }

    pub fn ms(self: Duration) u64 {
        return self.ticks * (std.time.ms_per_s / ticks_per_s);
    }

    pub fn ns(self: Duration) u64 {
        return self.ticks * (std.time.ns_per_s / ticks_per_s);
    }

    pub fn format(
        self: Duration,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{}", .{std.fmt.fmtDuration(self.ns())});
    }
};

fn parseHexString(comptime T: type, comptime length: usize, str: []const u8) ![length]T {
    var arr: [length]T = undefined;
    if (str.len != length * @sizeOf(T) * 2 + 1 or str[0] != '$') return error.InvalidFormat;
    for (arr) |*item, i| {
        item.* = try std.fmt.parseInt(T, str[i * @sizeOf(T) * 2 + 1 .. (i + 1) * @sizeOf(T) * 2 + 1], 16);
    }

    return arr;
}

fn parseDotString(comptime T: type, comptime length: usize, str: []const u8) ![length]T {
    var arr: [length]T = undefined;
    var it = std.mem.split(u8, str, ".");
    var i: usize = 0;
    while (it.next()) |part| {
        if (i == length) {
            return error.UnexpectedCharacter;
        }
        arr[i] = try std.fmt.parseInt(T, part, 10);
        i += 1;
    }

    return arr;
}

pub const MacAddress = struct {
    addr: [6]u8,

    pub fn init(addr: [6]u8) MacAddress {
        return .{.addr = addr};
    }

    pub fn parse(str: []const u8) !MacAddress {
        return init(try parseHexString(u8, 6, str));
    }

    pub fn format(
        self: MacAddress,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{X}:{X}:{X}:{X}:{X}:{X}", .{
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5],
        });
    }

    pub fn eql(a: MacAddress, b: MacAddress) bool {
        return std.mem.eql(u8, &a.addr, &b.addr);
    }
};

pub const Ipv4Address = struct {
    addr: [4]u8,

    pub const zero = init(.{0, 0, 0, 0});

    pub fn init(addr: [4]u8) Ipv4Address {
        return .{.addr = addr};
    }

    pub fn parse(str: []const u8) !Ipv4Address {
        return init(try parseHexString(u8, 4, str));
    }

    pub fn parseOid(str: []const u8) !Ipv4Address {
        return init(try parseDotString(u8, 4, str));
    }

    pub fn format(
        self: Ipv4Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{}.{}.{}.{}", .{
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
        });
    }

    pub fn eql(a: Ipv4Address, b: Ipv4Address) bool {
        return std.mem.eql(u8, &a.addr, &b.addr);
    }
};

pub const Ipv6Address = struct {
    addr: [8]u16,

    pub const zero = init(.{0, 0, 0, 0, 0, 0, 0, 0});

    pub fn init(addr: [8]u16) Ipv6Address {
        return .{.addr = addr};
    }

    pub fn parse(str: []const u8) !Ipv6Address {
        return init(try parseHexString(u16, 8, str));
    }

    pub fn parseOid(str: []const u8) !Ipv6Address {
        var addr = @bitCast([8]u16, try parseDotString(u8, 16, str));
        for (&addr) |*part| {
            part.* = @byteSwap(u16, part.*);
        }
        return init(addr);
    }

    pub fn format(
        self: Ipv6Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        var abbrev = false;
        for (self.addr) |part, i| {
            if (part == 0) {
                if (!abbrev) {
                    try writer.writeAll(if (i == 0) "::" else ":");
                    abbrev = true;
                }
                continue;
            }
            try writer.print("{X}", .{part});
            if (i != self.addr.len - 1) {
                try writer.writeByte(':');
            }
        }
    }

    pub fn eql(a: Ipv6Address, b: Ipv6Address) bool {
        return std.mem.eql(u16, &a.addr, &b.addr);
    }

    pub fn isLinkLocal(self: Ipv6Address) bool {
        return self.addr[0] == 0xFE80;
    }
};
