pub const MAX_MESSAGE_SIZE: usize = 128 * 1024; // 128 KB
pub const PIPE_NAME: &str = "\\\\.\\pipe\\UDSCredsComms";
pub const PIPE_BUFFER: u32 = 1024;
pub const MAGIC_HEADER: u32 = 0x09122009;
