
// #![recursion_limit = "1024"]

use rmp::encode::ValueWriteError;
use rmp::decode::ValueReadError;
use rmp::decode::NumValueReadError;
use std::io::Error;

error_chain!{}

#[derive(Debug)]
pub enum ReadError {
    InvalidMarker,
    InvalidData,
    TypeMismatch,
    Undef,
}

/// TODO proper error-structure
#[derive(Debug)]
pub enum CodecError {
    Read(ReadError),
    Write,
}

impl From<ValueWriteError> for CodecError {
    fn from(_e: ValueWriteError) -> CodecError { CodecError::Write }
}

impl From<ValueReadError> for CodecError {
    fn from(_e: ValueReadError) -> CodecError { CodecError::Read(ReadError::Undef) }
}

impl From<Error> for CodecError {
    fn from(_e: Error) -> CodecError { CodecError::Read(ReadError::Undef) }
}

impl From<NumValueReadError> for CodecError {
    fn from(_e: NumValueReadError) -> CodecError { CodecError::Read(ReadError::Undef) }
}
