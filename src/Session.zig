const std = @import("std");
const hzzp = @import("hzzp");
const oid = @import("oid.zig");
const ar = @import("ar.zig");
const mib2 = @import("mib2.zig");

const Stream = std.net.Stream;
const Address = std.net.Address;
const base64 = std.base64.standard;
const log = std.log.scoped(.session);
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const assert = std.debug.assert;
const epoch = std.time.epoch;

const Date = oid.Date;
const Duration = oid.Duration;
const MacAddress = oid.MacAddress;
const Ipv4Address = oid.Ipv4Address;
const Ipv6Address = oid.Ipv6Address;

const Session = @This();

// TODO Uri-safe encoding where required.

const AlreadyLoggedInUser = enum(u8) {
    local_user = 1,
    other_remote_user_terminatable = 2,
    other_local_user = 3,
    other_remote_user = 4,
    unknown,
};

const port = 80;
const buffer_size = 4096;

const BufferedWriter = std.io.BufferedWriter(buffer_size, Stream.Writer);
const BufferedReader = std.io.BufferedReader(buffer_size, Stream.Reader);
const ResponseParser = hzzp.parser.response.ResponseParser(BufferedReader.Reader);

// Note: Field names reflect json structure in credential.
const Attrs = struct {
    unique: []const u8,
    family: []const u8,
    modelname: []const u8,
    name: []const u8,
    tech: bool,
    moca: u32,
    wifi: u32,
    conType: []const u8,
    muti: ?[]const u8 = null,
    gwWan: []const u8,
    DefPasswdChanged: []const u8,
};

allocator: Allocator,

host: []const u8,
stream: Stream,
br: BufferedReader,
bw: BufferedWriter,
response_buffer: [buffer_size]u8,
response_parser: ResponseParser,
full_response_buffer: std.ArrayListUnmanaged(u8),

nonce: u32,

credential: ?[]const u8,

// Contents only valid if credential is not null.
attrs: Attrs,

pub fn init(allocator: Allocator, host: []const u8) !*Session {
    log.debug("connecting to modem at {s}:{}", .{host, port});

    const stream = try std.net.tcpConnectToHost(allocator, host, port);
    errdefer stream.close();

    var self = try allocator.create(Session);
    errdefer allocator.free(self);

    self.allocator = allocator;
    self.host = host;
    self.stream = stream;
    self.br = .{.unbuffered_reader = self.stream.reader()};
    self.bw = .{.unbuffered_writer = self.stream.writer()};
    self.response_parser = ResponseParser.init(&self.response_buffer, self.br.reader());
    self.response_parser.done = true; // To make drainResponse work on the first request.
    self.full_response_buffer = .{};

    self.refreshNonce();
    self.credential = null;

    return self;
}

pub fn close(self: *Session) void {
    const allocator = self.allocator;
    self.full_response_buffer.deinit(self.allocator);
    if (self.credential) |credential| {
        allocator.free(credential);
        std.json.parseFree(Attrs, self.attrs, .{.allocator = self.allocator});
    }
    self.stream.close();
    allocator.destroy(self);
}

const Response = struct {
    status: u16,
    data: []const u8,
};

// Return value is valid until the next call to get()
fn get(self: *Session, endpoint: []const u8, query_params: anytype) !Response {
    self.response_parser.reset();

    var writer = self.bw.writer();

    try writer.writeAll("GET ");
    try writer.writeAll(endpoint);
    try writer.writeByte('?');

    // Note: Some query parameters need to be before the nonce
    inline for (std.meta.fields(@TypeOf(query_params))) |field, i| {
        if (i != 0) {
            try writer.writeByte('&');
        }
        try writer.writeAll(field.name ++ "=");
        const value = @field(query_params, field.name);
        switch (field.field_type) {
            []const u8, []u8 => try writer.writeAll(value),
            oid.Scalar => try writer.print("{s}.{};", .{value.oid, value.index}),
            []const oid.Scalar, []oid.Scalar => {
                for (value) |item| {
                    try writer.print("{s}.{};", .{item.oid, item.index});
                }
            },
            oid.Vector => try writer.print("{s}", .{value.oid}),
            []const oid.Vector, []oid.Vector => {
                for (value) |item| {
                    try writer.print("{s};", .{item.oid});
                }
            },
            else => @compileError("Invalid query parameter type " ++ @typeName(field.field_type)),
        }
    }

    if (std.meta.fields(@TypeOf(query_params)).len > 0) {
        try writer.writeByte('&');
    }
    try writer.print("_n={}", .{ self.nonce });

    try writer.print(" HTTP/1.1\r\nHost: {s}\r\n", .{self.host});
    if (self.credential) |c| {
        try writer.print("Cookie: credential={s}\r\n", .{c});
    }
    try writer.writeAll("\r\n");
    try self.bw.flush();

    self.full_response_buffer.items.len = 0;
    var status: u16 = undefined;

    const payload = while (try self.response_parser.next()) |event| {
        switch (event) {
            .status => |e| status = e.code,
            .payload => |e| {
                if (e.final and self.full_response_buffer.items.len == 0)
                    break e.data;

                try self.full_response_buffer.appendSlice(self.allocator, e.data);

                if (e.final) {
                    break self.full_response_buffer.items;
                }
            },
            else => {},
        }
    } else &[_]u8{};

    return Response{.status = status, .data = payload};
}

fn checkHasCredential(self: Session) !void {
    if (self.credential == null) return error.NotLoggedIn;
}

pub fn refreshNonce(self: *Session) void {
    var prng = std.rand.DefaultPrng.init(@bitCast(u64, std.time.milliTimestamp()));
    // Modem nonce consists of 5 digits in the original implementation.
    self.nonce = prng.random().intRangeLessThan(u32, 10_000, 100_000);
    log.debug("nonce: {}", .{ self.nonce });
}

pub fn login(self: *Session, username: []const u8, password: []const u8) !void {
    if (self.credential) |credential| {
        self.allocator.free(credential);
        std.json.parseFree(Attrs, self.attrs, .{.allocator = self.allocator});
    }

    const arg_plain = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ username, password });
    defer self.allocator.free(arg_plain);

    const arg = try self.allocator.alloc(u8, base64.Encoder.calcSize(arg_plain.len));
    defer self.allocator.free(arg);
    _ = base64.Encoder.encode(arg, arg_plain);

    const response = try self.get("/login", .{.arg = arg});
    if (response.status != 200) {
        log.debug("failed to login, got status {}", .{ response.status });
        return error.LoginFailed;
    } else if (std.mem.eql(u8, response.data, "LockedOut")) {
        return error.LockedOut;
    }

    self.credential = try self.allocator.dupe(u8, response.data);
    log.debug("login successful, got credential {s}", .{ self.credential.? });
    try self.decodeCredential();
}

fn decodeCredential(self: *Session) !void {
    var plain_credential = try self.allocator.alloc(u8, try base64.Decoder.calcSizeForSlice(self.credential.?));
    defer self.allocator.free(plain_credential);
    try base64.Decoder.decode(plain_credential, self.credential.?);

    log.debug("plain credential: {s}", .{plain_credential});

    @setEvalBranchQuota(10000);
    var tokens = std.json.TokenStream.init(plain_credential);
    self.attrs = try std.json.parse(Attrs, &tokens, .{ .allocator = self.allocator });
}

pub fn alreadyLoggedInUserType(self: Session) !?AlreadyLoggedInUser {
    try self.checkHasCredential();

    const muti = self.attrs.muti orelse return null;

    const is_gw_wan = std.mem.eql(u8, self.attrs.gwWan, "t");
    const contype_is_lan = std.mem.eql(u8, self.attrs.conType, "LAN");
    const muti_is_gw_wan = std.mem.eql(u8, muti, "GW_WAN");
    const muti_is_lan = std.mem.eql(u8, muti, "LAN");

    if (!is_gw_wan and contype_is_lan and muti_is_gw_wan) {
        return AlreadyLoggedInUser.local_user;
    } else if (is_gw_wan and muti_is_lan) {
        return AlreadyLoggedInUser.other_remote_user_terminatable;
    } else if (!is_gw_wan and contype_is_lan and muti_is_lan) {
        return AlreadyLoggedInUser.other_local_user;
    } else if (is_gw_wan and muti_is_gw_wan) {
        return AlreadyLoggedInUser.other_remote_user;
    } else {
        return AlreadyLoggedInUser.unknown;
    }
}

pub fn logout(self: *Session) !void {
    try self.checkHasCredential();
    const response = try self.get("/logout", .{});
    if (response.status == 401) {
        return error.Unauthorized;
    } else if (response.status != 500) {
        log.debug("query returned unexpected status {}", .{response.status});
        return error.UnexpectedResponse;
    }
}

fn expectJsonToken(expected: std.meta.Tag(std.json.Token), maybe_actual: ?std.json.Token) !void {
    const actual = maybe_actual orelse return error.UnexpectedResponse;
    if (actual != expected) return error.UnexpectedResponse;
}

pub const QueryResult = struct {
    arena: ArenaAllocator.State,
    results: [][]u8,

    pub fn deinit(self: QueryResult, allocator: Allocator) void {
        self.arena.promote(allocator).deinit();
    }
};

pub fn query(self: *Session, ra: Allocator, items: []const oid.Scalar) !QueryResult {
    assert(items.len >= 1);
    try self.checkHasCredential();
    const response = try self.get("/snmpGet", .{
        .oids = items
    });

    if (response.status == 401) {
        return error.Unauthorized;
    } else if (response.status != 200 ){
        log.debug("query returned unexpected status {}", .{response.status});
        return error.UnexpectedResponse;
    }

    if (std.mem.startsWith(u8, response.data, "query returned Error in OID formatting!")) {
        log.err("query oid was formatted incorrectly", .{});
        unreachable; // If the server returned the above error, there was a bug in this program.
    }

    var arena = ArenaAllocator.init(ra);
    errdefer arena.deinit();

    const results = try arena.allocator().alloc([]u8, items.len);

    // We don't really need a full JSON parser here. The result will look like `{<oid>:<value>[, <oid>:<value>]?}`.
    var tokens = std.json.TokenStream.init(response.data);

    // For now, assume that the result is ordered the same as the query.
    try expectJsonToken(.ObjectBegin, try tokens.next());
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        try expectJsonToken(.String, try tokens.next());
        const tok = try tokens.next();
        try expectJsonToken(.String, tok);

        const text = tok.?.String.slice(response.data, tokens.i - 1);
        const decoded_length = tok.?.String.decodedLength();

        results[i] = try arena.allocator().alloc(u8, decoded_length);
        try std.json.unescapeValidString(results[i], text);
    }
    try expectJsonToken(.ObjectEnd, try tokens.next());

    return QueryResult{
        .arena = arena.state,
        .results = results
    };
}

pub const WalkResult = struct {
    const Entry = struct {
        keys: [][]u8,
        values: [][]u8,
    };

    arena: ArenaAllocator.State,
    results: []Entry,

    pub fn deinit(self: WalkResult, allocator: Allocator) void {
        self.arena.promote(allocator).deinit();
    }
};

pub fn walk(self: *Session, ra: Allocator, vectors: []const oid.Vector) !WalkResult {
    assert(vectors.len >= 1);
    try self.checkHasCredential();
    const response = try self.get("/walk", .{
        .oids = vectors
    });

    if (response.status == 401) {
        return error.Unauthorized;
    } else if (response.status != 200) {
        log.debug("query returned unexpected status {}", .{response.status});
        return error.UnexpectedResponse;
    }

    var arena = ArenaAllocator.init(ra);
    errdefer arena.deinit();

    const results = try arena.allocator().alloc(WalkResult.Entry, vectors.len);
    var current_list = std.MultiArrayList(struct{ key: []u8, value: []u8 }){};

    // We don't really need a full JSON parser here. The result will look like `{<oid>:<value>[, <oid>:<value>]?}`.
    var tokens = std.json.TokenStream.init(response.data);

    // For now, assume that the result is ordered the same as the query.
    try expectJsonToken(.ObjectBegin, try tokens.next());
    var i: usize = 0;
    while (true) {
        const key_tok = try tokens.next();
        try expectJsonToken(.String, key_tok);
        const key_text = key_tok.?.String.slice(response.data, tokens.i - 1);
        const key_dlen = key_tok.?.String.decodedLength();

        const val_tok = try tokens.next();
        try expectJsonToken(.String, val_tok);
        const val_text = val_tok.?.String.slice(response.data, tokens.i - 1);
        const val_dlen = val_tok.?.String.decodedLength();

        // We don't expect any escapes in the initial oid part of the key at least, so check
        // that without allocating.

        if (!std.mem.startsWith(u8, key_text, vectors[i].oid)) {
            const slice = current_list.toOwnedSlice();
            results[i].keys = slice.items(.key);
            results[i].values = slice.items(.value);
            i += 1;

            if (i == vectors.len) {
                if (!std.mem.eql(u8, key_text, "1") or !std.mem.eql(u8, val_text, "Finish")) {
                    return error.UnexpectedResponse;
                }

                try expectJsonToken(.ObjectEnd, try tokens.next());
                break;
            }
        }

        const key = try arena.allocator().alloc(u8, key_dlen - vectors[i].oid.len);
        const val = try arena.allocator().alloc(u8, val_dlen);

        try std.json.unescapeValidString(key, key_text[vectors[i].oid.len..]);
        try std.json.unescapeValidString(val, val_text);

        try current_list.append(arena.allocator(), .{.key = key, .value = val});
    }

    return WalkResult{
        .arena = arena.state,
        .results = results,
    };
}

const Status = struct {
    arena: ArenaAllocator.State,

    admin_timeout: u64,
    tz_utc_offset: i8,
    language: []u8,
    modem_name: []u8,
    serial_number: []u8,
    hardware_version: []u8,
    firmware_version: []u8,
    current_time: Date,
    uptime: Duration,
    cable_mac: MacAddress,

    pub fn deinit(self: Status, ra: Allocator) void {
        self.arena.promote(ra).deinit();
    }

    pub fn dump(self: Status, writer: anytype) !void {
        try writer.print("admin timeout: {}\n", .{ self.admin_timeout });
        try writer.print("timezone utc offset: {}\n", .{ self.tz_utc_offset });
        try writer.print("language: {s}\n", .{ self.language });
        try writer.print("modem name: {s}\n", .{ self.modem_name });
        try writer.print("serial number: {s}\n", .{ self.serial_number });
        try writer.print("hardware version: {s}\n", .{ self.hardware_version });
        try writer.print("firmware version: {s}\n", .{ self.firmware_version });
        try writer.print("current time: {}\n", .{ self.current_time });
        try writer.print("uptime: {}\n", .{ self.uptime });
        try writer.print("cable mac address: {}\n", .{ self.cable_mac });
    }
};

pub fn modemStatus(self: *Session, ra: Allocator) !Status {
    const result = try self.query(ra, &.{
        ar.sys_cfg.admin_timeout,
        ar.sys_cfg.time_zone_utc_offset,
        ar.sys_cfg.language,
        ar.sys_cfg.name,
        ar.sys_cfg.serial_number,
        ar.sys_cfg.boot_code_version,
        ar.sys_cfg.hardware_version,
        ar.sys_cfg.firmware_version,
        ar.sys_cfg.current_time,
        mib2.system.uptime,
        mib2.interfaces.if_table.if_entry.phys_address.at(2),
    });
    errdefer result.deinit(ra);
    const results = result.results;

    return Status{
        .arena = result.arena,
        .admin_timeout = try std.fmt.parseInt(u64, results[0], 10),
        .tz_utc_offset = try std.fmt.parseInt(i8, results[1], 10),
        .language = results[2],
        .modem_name = results[3],
        .serial_number = results[4],
        .hardware_version = results[5],
        .firmware_version = results[7],
        .current_time = try Date.parse(results[8]),
        .uptime = try Duration.parse(results[9]),
        .cable_mac = try MacAddress.parse(results[10]),
    };
}

const WanStatus = struct {
    mac: MacAddress,
    address_type: enum { v6, v4 },
    ipv4: struct {
        address: Ipv4Address,
        prefix: u5,
        default_gateway: Ipv4Address,
        lease_time: Duration,
        lease_expire: Date,
    },
    ipv6: struct {
        address: Ipv6Address,
        prefix: u7,
        default_gateway: Ipv6Address,
        lease_time: Duration,
        lease_expire: Date,
    },

    pub fn dump(self: WanStatus, writer: anytype) !void {
        try writer.print("mac: {}\n", .{ self.mac });
        try writer.print("ip type: {s}\n", .{ @tagName(self.address_type) });
        try writer.print("ipv4 address: {}/{}\n", .{ self.ipv4.address, self.ipv4.prefix });
        try writer.print("ipv4 default gateway: {}\n", .{ self.ipv4.address });
        try writer.print("ipv4 lease time: {}\n", .{ self.ipv4.lease_time });
        try writer.print("ipv4 lease expire: {}\n", .{ self.ipv4.lease_expire });
        try writer.print("ipv6 address: {}/{}\n", .{ self.ipv6.address, self.ipv6.prefix });
        try writer.print("ipv6 default gateway: {}\n", .{ self.ipv6.address });
        try writer.print("ipv6 lease time: {}\n", .{ self.ipv6.lease_time });
        try writer.print("ipv6 lease expire: {}\n", .{ self.ipv6.lease_expire });
    }
};

pub fn wanStatus(self: *Session, ra: Allocator) !WanStatus {
    const result = try self.query(ra, &.{
        ar.wan_config.if_mac_addr,
        ar.wan_config.v6,

        ar.wan_config.current_table.entry.ip_addr.at(1),
        ar.wan_config.current_table.entry.prefix.at(1),
        ar.wan_config.current_table.entry.gw.at(1),
        ar.wan_config.dhcp_objects.duration,
        ar.wan_config.dhcp_objects.expire,

        ar.wan_config.current_table.entry.ip_addr.at(2),
        ar.wan_config.current_table.entry.prefix.at(2),
        ar.wan_config.current_table.entry.gw.at(2),
        ar.wan_config.dhcp_objects.duration_v6,
        ar.wan_config.dhcp_objects.expire_v6,
    });
    defer result.deinit(ra);
    const results = result.results;

    return WanStatus{
        .mac = try MacAddress.parse(results[0]),
        .address_type = if (std.mem.eql(u8, results[1], "1")) .v6 else .v4,
        .ipv4 = .{
            .address = try Ipv4Address.parse(results[2]),
            .prefix = try std.fmt.parseInt(u5, results[3], 10),
            .default_gateway = try Ipv4Address.parse(results[4]),
            .lease_time = try Duration.parse(results[5]),
            .lease_expire = try Date.parse(results[6]),
        },
        .ipv6 = .{
            .address = try Ipv6Address.parse(results[7]),
            .prefix = try std.fmt.parseInt(u7, results[8], 10),
            .default_gateway = try Ipv6Address.parse(results[9]),
            .lease_time = try Duration.parse(results[10]),
            .lease_expire = try Date.parse(results[11]),
        },
    };
}

const Device = struct {
    host_name: []const u8,
    // Note, might not include ALL the addresses a particular device has.
    addr_v4: Ipv4Address,
    addr_v6: Ipv6Address,
    link_addr_v6: Ipv6Address,
    mac: MacAddress,
};

const Devices = struct {
    arena: ArenaAllocator.State,
    devices: []Device,

    pub fn deinit(self: Devices, ra: Allocator) void {
        self.arena.promote(ra).deinit();
    }

    pub fn dump(self: Devices, writer: anytype) !void {
        for (self.devices) |dev, i| {
            try writer.print("device {}:\n", .{i});
            try writer.print("  host name: {s}\n", .{dev.host_name});
            try writer.print("  ipv4 address: {}\n", .{dev.addr_v4});
            try writer.print("  ipv6 address: {}\n", .{dev.addr_v6});
            try writer.print("  ipv6 link-local address: {}\n", .{dev.link_addr_v6});
            try writer.print("  mac address: {}\n", .{dev.mac});
        }
    }
};

pub fn devices(self: *Session, ra: Allocator) !Devices {
    const client = ar.lan_config.client_objects.lan_client_table.entry;
    const result = try self.walk(ra, &.{
        client.mac,
        client.host_name,
    });
    errdefer result.deinit(ra);
    const results = result.results;

    // Note: This walk returns three lists concatenated: The field for the ipv4 address, the field for the ipv6 address,
    // and the field for the link-local ipv6 address.
    // The key for the ipv4 list starts with .200.1.4., the remainder is the ipv4 address in decimal separated by dots.
    // The key for the ipv6 lists starts with .200.2.16., the remainder is the ipv6 address in decimal every u8 separated by dots.
    // Note: The lists might not be of equal length!
    // We will identify devices by mac address and by the key.
    const ipv4_prefix = ".200.1.4.";
    const ipv6_prefix = ".200.2.16.";

    var key_to_dev = std.StringHashMap(usize).init(ra);
    defer key_to_dev.deinit();
    // Assume that all connected devices will have a mac address...
    try key_to_dev.ensureUnusedCapacity(@intCast(u32, results[0].keys.len));

    const arena = result.arena.promote(ra).allocator();

    var devs = std.ArrayList(Device).init(arena);
    errdefer devs.deinit();

    for (results[0].keys) |key, i| {
        const mac = try MacAddress.parse(results[0].values[i]);

        // TODO: Maybe make another hash map? Probably not even worth it.
        const index = for (devs.items) |dev, j| {
            if (dev.mac.eql(mac)) {
                break j;
            }
        } else blk: {
            try devs.append(.{
                .host_name = "",
                .addr_v4 = Ipv4Address.zero,
                .addr_v6 = Ipv6Address.zero,
                .link_addr_v6 = Ipv6Address.zero,
                .mac = mac,
            });
            break :blk devs.items.len - 1;
        };

        key_to_dev.putAssumeCapacityNoClobber(key, index);
        const dev = &devs.items[index];

        // We can already insert the address by extracting it from the key.
        if (std.mem.startsWith(u8, key, ipv4_prefix)) {
            const addr = try Ipv4Address.parseOid(key[ipv4_prefix.len..]);
            if (dev.addr_v4.eql(Ipv4Address.zero)) {
                dev.addr_v4 = addr;
            }
        } else if (std.mem.startsWith(u8, key, ipv6_prefix)) {
            const addr = try Ipv6Address.parseOid(key[ipv6_prefix.len..]);
            if (addr.isLinkLocal()) {
                if (dev.link_addr_v6.eql(Ipv6Address.zero)) {
                    dev.link_addr_v6 = addr;
                }
            } else if (dev.addr_v6.eql(Ipv6Address.zero)) {
                dev.addr_v6 = addr;
            }
        } else {
            log.debug("Invalid key {s}", .{key});
            return error.UnexpectedResponse;
        }
    }

    for (results[1].keys) |key, i| {
        const host_name = results[1].values[i];
        const index = key_to_dev.get(key) orelse {
            log.debug("Walk returned hostname for device {s} which has no mac address", .{ key });
            continue;
        };
        const dev = &devs.items[index];

        if (dev.host_name.len == 0) {
             dev.host_name = host_name;
        }
    }

    return Devices{
        .arena = result.arena,
        .devices = devs.toOwnedSlice(),
    };
}
