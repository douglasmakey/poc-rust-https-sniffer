// https://datatracker.ietf.org/doc/html/rfc6066#section-4
// https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html
pub const MAX_BUF_SIZE: usize = 16384;
pub const TASK_COMM_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Data {
    pub kind: Kind,
    pub len: i32,
    pub buf: [u8; MAX_BUF_SIZE],
    pub comm: [u8; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl std::fmt::Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Convert 'comm' and 'buf' fields to strings for display.
        // 'String::from_utf8_lossy' will replace invalid UTF-8 sequences with U+FFFD REPLACEMENT CHARACTER.
        let comm_str = String::from_utf8_lossy(&self.comm);
        let data_str = String::from_utf8_lossy(&self.buf[..self.len as usize]);

        // Write the formatted output to the formatter.
        // Adjust formatting as needed for clarity and readability.
        write!(
            f,
            "Kind: {:?}, Length: {}, Command: {}, Data: {}",
            self.kind, self.len, comm_str, data_str
        )
    }
}
