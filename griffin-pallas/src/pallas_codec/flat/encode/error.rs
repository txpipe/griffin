use thiserror_no_std::Error;

use alloc::string::String;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Buffer is not byte aligned")]
    BufferNotByteAligned,
    #[error("{0}")]
    Message(String),
}
