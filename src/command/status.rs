use crate::command::Reply;

/// Return the status of our server.
#[derive(Debug)]
pub struct StatusReply {}

impl Reply for StatusReply {
    fn to_message_bytes(&self) -> &[u8] {
        "ok".as_bytes()
    }
}

#[test]
fn reply_string() {
    assert_eq!(StatusReply {}.to_message_bytes(), b"ok");
}
