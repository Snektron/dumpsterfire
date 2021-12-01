const oid = @import("oid.zig");
const scalar = oid.scalar;
const vector = oid.vector;

pub const system = struct {
    pub const uptime = scalar("1.3.6.1.2.1.1.3", 0);
};

pub const interfaces = struct {
    pub const if_table = struct {
        pub const if_entry = struct {
            pub const phys_address = vector("1.3.6.1.2.1.2.2.1.6", 0);
        };
    };
};
