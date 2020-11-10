mod status;

/// A command we receive from a client.
#[derive(Debug)]
pub enum Command {
    /// Return the current status of the server.
    Status,
}

impl Command {
    /// Get a reply from a command.
    pub fn reply(&self) -> impl Reply {
        match self {
            Command::Status => status::StatusReply {},
        }
    }
}

/// Signifies that a type is a reply.
pub trait Reply {
    /// Convert to a binary format we can send back to a client.
    fn to_message_bytes(&self) -> &[u8];
}

#[test]
fn command_reply_string() {
    assert_eq!(Command::Status.reply().to_message_bytes(), b"ok");
}
