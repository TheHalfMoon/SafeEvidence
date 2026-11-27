//! The framed protocol between the vault and the Linux keyring helper, over stdin and stdout.
//!
//! The helper stores one opaque record per protector ID. The vault keeps the record format and all
//! binding and policy checks, so the helper never needs to interpret key material.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

pub const VERSION: u8 = 1;
pub const MAX_FRAME_BYTES: usize = 4096;
pub const PROTECTOR_ID_BYTES: usize = 16;

pub type ProtectorId = [u8; PROTECTOR_ID_BYTES];
pub type SecretBytes = Zeroizing<Vec<u8>>;

const OP_ENSURE_UNLOCKED: u8 = 1;
const OP_READ: u8 = 2;
const OP_CREATE: u8 = 3;
const OP_DELETE: u8 = 4;

const REPLY_DONE: u8 = 0;
const REPLY_NO_RECORD: u8 = 1;
const REPLY_RECORD: u8 = 2;
const REPLY_FAILED: u8 = 3;

/// A failure the helper reports. `Protocol` means a frame could not be understood.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Unavailable,
    Locked,
    Denied,
    ItemMissing,
    OwnerMismatch,
    PolicyMismatch,
    CorruptOrTampered,
    Protocol,
}

impl WireError {
    const fn code(self) -> u8 {
        match self {
            Self::Unavailable => 1,
            Self::Locked => 2,
            Self::Denied => 3,
            Self::OwnerMismatch => 4,
            Self::PolicyMismatch => 5,
            Self::CorruptOrTampered => 6,
            Self::Protocol => 7,
            Self::ItemMissing => 8,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Unavailable),
            2 => Some(Self::Locked),
            3 => Some(Self::Denied),
            4 => Some(Self::OwnerMismatch),
            5 => Some(Self::PolicyMismatch),
            6 => Some(Self::CorruptOrTampered),
            7 => Some(Self::Protocol),
            8 => Some(Self::ItemMissing),
            _ => None,
        }
    }
}

#[derive(Eq, PartialEq)]
pub enum Op {
    EnsureUnlocked,
    Read,
    Create(SecretBytes),
    Delete,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Request {
    pub protector_id: ProtectorId,
    pub op: Op,
}

#[derive(Eq, PartialEq)]
pub enum Reply {
    Done,
    NoRecord,
    Record(SecretBytes),
    Failed(WireError),
}

// By hand, so record bytes cannot reach a log or a panic message.
impl std::fmt::Debug for Op {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EnsureUnlocked => "EnsureUnlocked",
            Self::Read => "Read",
            Self::Create(_) => "Create([REDACTED])",
            Self::Delete => "Delete",
        })
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done => formatter.write_str("Done"),
            Self::NoRecord => formatter.write_str("NoRecord"),
            Self::Record(_) => formatter.write_str("Record([REDACTED])"),
            Self::Failed(error) => write!(formatter, "Failed({error:?})"),
        }
    }
}

/// What the helper does with each request.
pub trait Backend {
    /// Fails unless the store is available and already unlocked. It must never unlock it.
    fn ensure_unlocked(&mut self, id: &ProtectorId) -> Result<(), WireError>;
    fn read(&mut self, id: &ProtectorId) -> Result<Option<SecretBytes>, WireError>;
    fn create(&mut self, id: &ProtectorId, record: &[u8]) -> Result<(), WireError>;
    /// Deletes the record and confirms it is gone. A missing record is not a failure.
    fn delete(&mut self, id: &ProtectorId) -> Result<(), WireError>;
}

#[must_use]
pub fn encode_request(request: &Request) -> SecretBytes {
    let (op, payload): (u8, &[u8]) = match &request.op {
        Op::EnsureUnlocked => (OP_ENSURE_UNLOCKED, &[]),
        Op::Read => (OP_READ, &[]),
        Op::Create(record) => (OP_CREATE, record),
        Op::Delete => (OP_DELETE, &[]),
    };
    let mut frame = Zeroizing::new(Vec::with_capacity(2 + PROTECTOR_ID_BYTES + payload.len()));
    frame.push(VERSION);
    frame.push(op);
    frame.extend_from_slice(&request.protector_id);
    frame.extend_from_slice(payload);
    frame
}

/// # Errors
/// Returns `Protocol` for a wrong version, an unknown operation, or trailing or missing bytes.
pub fn decode_request(frame: &[u8]) -> Result<Request, WireError> {
    let header = 2 + PROTECTOR_ID_BYTES;
    if frame.len() < header || frame[0] != VERSION {
        return Err(WireError::Protocol);
    }
    let protector_id: ProtectorId = frame[2..header]
        .try_into()
        .map_err(|_| WireError::Protocol)?;
    let payload = &frame[header..];
    let op = match (frame[1], payload.is_empty()) {
        (OP_ENSURE_UNLOCKED, true) => Op::EnsureUnlocked,
        (OP_READ, true) => Op::Read,
        (OP_DELETE, true) => Op::Delete,
        (OP_CREATE, false) => Op::Create(Zeroizing::new(payload.to_vec())),
        _ => return Err(WireError::Protocol),
    };
    Ok(Request { protector_id, op })
}

#[must_use]
pub fn encode_reply(reply: &Reply) -> SecretBytes {
    let mut frame = Zeroizing::new(vec![VERSION]);
    match reply {
        Reply::Done => frame.push(REPLY_DONE),
        Reply::NoRecord => frame.push(REPLY_NO_RECORD),
        Reply::Record(record) => {
            frame.push(REPLY_RECORD);
            frame.extend_from_slice(record);
        }
        Reply::Failed(error) => {
            frame.push(REPLY_FAILED);
            frame.push(error.code());
        }
    }
    frame
}

/// # Errors
/// Returns `Protocol` for a wrong version, an unknown reply, or trailing or missing bytes.
pub fn decode_reply(frame: &[u8]) -> Result<Reply, WireError> {
    let [VERSION, tag, payload @ ..] = frame else {
        return Err(WireError::Protocol);
    };
    match (*tag, payload) {
        (REPLY_DONE, []) => Ok(Reply::Done),
        (REPLY_NO_RECORD, []) => Ok(Reply::NoRecord),
        (REPLY_RECORD, [_, ..]) => Ok(Reply::Record(Zeroizing::new(payload.to_vec()))),
        (REPLY_FAILED, [code]) => WireError::from_code(*code)
            .map(Reply::Failed)
            .ok_or(WireError::Protocol),
        _ => Err(WireError::Protocol),
    }
}

/// Writes one length-prefixed frame.
///
/// # Errors
/// Fails on an oversized frame or an I/O error.
pub fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let length =
        u32::try_from(frame.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(frame)?;
    writer.flush()
}

/// Reads one frame. `None` means the peer closed cleanly between frames.
///
/// # Errors
/// Fails on an oversized length, a frame cut short, or an I/O error.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<SecretBytes>> {
    let mut length = [0_u8; 4];
    let mut first = 0;
    while first == 0 {
        match reader.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(count) => first = count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut length[1..])?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut frame = Zeroizing::new(vec![0_u8; length]);
    reader.read_exact(&mut frame)?;
    Ok(Some(frame))
}

fn dispatch<B: Backend>(backend: &mut B, request: &Request) -> Reply {
    let id = &request.protector_id;
    let result = match &request.op {
        Op::EnsureUnlocked => backend.ensure_unlocked(id).map(|()| Reply::Done),
        Op::Read => backend
            .read(id)
            .map(|record| record.map_or(Reply::NoRecord, Reply::Record)),
        Op::Create(record) => backend.create(id, record).map(|()| Reply::Done),
        Op::Delete => backend.delete(id).map(|()| Reply::Done),
    };
    result.unwrap_or_else(Reply::Failed)
}

/// Answers requests until the peer closes. A frame it cannot understand gets `Protocol`, and then the
/// loop ends, because the stream can no longer be trusted.
///
/// # Errors
/// Returns I/O errors, including an oversized or cut-short frame.
pub fn serve<R: Read, W: Write, B: Backend>(
    reader: &mut R,
    writer: &mut W,
    backend: &mut B,
) -> io::Result<()> {
    while let Some(frame) = read_frame(reader)? {
        match decode_request(&frame) {
            Ok(request) => write_frame(writer, &encode_reply(&dispatch(backend, &request)))?,
            Err(error) => {
                write_frame(writer, &encode_reply(&Reply::Failed(error)))?;
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;

    const ID: ProtectorId = [7; PROTECTOR_ID_BYTES];

    fn secret(bytes: &[u8]) -> SecretBytes {
        Zeroizing::new(bytes.to_vec())
    }

    #[test]
    fn requests_round_trip() {
        for op in [
            Op::EnsureUnlocked,
            Op::Read,
            Op::Delete,
            Op::Create(secret(b"r")),
        ] {
            let request = Request {
                protector_id: ID,
                op,
            };
            assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
        }
    }

    #[test]
    fn replies_round_trip() {
        for reply in [
            Reply::Done,
            Reply::NoRecord,
            Reply::Record(secret(b"r")),
            Reply::Failed(WireError::Unavailable),
            Reply::Failed(WireError::Locked),
            Reply::Failed(WireError::Denied),
            Reply::Failed(WireError::ItemMissing),
            Reply::Failed(WireError::OwnerMismatch),
            Reply::Failed(WireError::PolicyMismatch),
            Reply::Failed(WireError::CorruptOrTampered),
            Reply::Failed(WireError::Protocol),
        ] {
            assert_eq!(decode_reply(&encode_reply(&reply)).unwrap(), reply);
        }
    }

    #[test]
    fn malformed_requests_are_refused() {
        let good = encode_request(&Request {
            protector_id: ID,
            op: Op::Read,
        });
        let mut wrong_version = good.to_vec();
        wrong_version[0] = 2;
        let mut unknown_op = good.to_vec();
        unknown_op[1] = 9;
        let mut trailing = good.to_vec();
        trailing.push(0);
        let empty_create = encode_request(&Request {
            protector_id: ID,
            op: Op::Create(secret(b"")),
        });
        for frame in [
            &[][..],
            &good[..good.len() - 1],
            &wrong_version,
            &unknown_op,
            &trailing,
            &empty_create,
        ] {
            assert_eq!(decode_request(frame).unwrap_err(), WireError::Protocol);
        }
    }

    #[test]
    fn malformed_replies_are_refused() {
        for frame in [
            &[][..],
            &[VERSION],
            &[2, REPLY_DONE],
            &[VERSION, 9],
            &[VERSION, REPLY_DONE, 0],
            &[VERSION, REPLY_NO_RECORD, 0],
            &[VERSION, REPLY_RECORD],
            &[VERSION, REPLY_FAILED],
            &[VERSION, REPLY_FAILED, 0],
            &[VERSION, REPLY_FAILED, 99],
            &[VERSION, REPLY_FAILED, 1, 1],
        ] {
            assert_eq!(decode_reply(frame).unwrap_err(), WireError::Protocol);
        }
    }

    #[test]
    fn frames_round_trip_and_clean_close_is_none() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"abc").unwrap();
        let mut reader = Cursor::new(buffer);
        assert_eq!(read_frame(&mut reader).unwrap().unwrap().as_slice(), b"abc");
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn oversized_or_cut_short_frames_fail() {
        let oversized = vec![0_u8; MAX_FRAME_BYTES + 1];
        assert!(write_frame(&mut Vec::new(), &oversized).is_err());
        write_frame(&mut Vec::new(), &vec![0_u8; MAX_FRAME_BYTES]).unwrap();
        let too_long = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
        assert!(read_frame(&mut Cursor::new(too_long)).is_err());
        assert!(read_frame(&mut Cursor::new([0_u8, 0])).is_err());
        assert!(read_frame(&mut Cursor::new([0_u8, 0, 0, 5, 1])).is_err());
    }

    #[test]
    fn a_frame_one_byte_over_the_limit_is_refused_even_when_all_its_bytes_arrive() {
        let mut stream = u32::try_from(MAX_FRAME_BYTES + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        stream.extend(vec![0_u8; MAX_FRAME_BYTES + 1]);
        let error = read_frame(&mut Cursor::new(stream)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn debug_output_never_contains_record_bytes() {
        let marker = b"SECRETMARKER";
        let request = Request {
            protector_id: ID,
            op: Op::Create(secret(marker)),
        };
        for text in [
            format!("{request:?}"),
            format!("{:?}", Reply::Record(secret(marker))),
        ] {
            assert!(text.contains("REDACTED"), "{text}");
            for byte in marker {
                assert!(!text.contains(&format!("{byte},")), "{text}");
            }
            assert!(!text.contains("SECRETMARKER"), "{text}");
        }
    }

    #[derive(Default)]
    struct Memory(HashMap<ProtectorId, Vec<u8>>);

    impl Backend for Memory {
        fn ensure_unlocked(&mut self, _id: &ProtectorId) -> Result<(), WireError> {
            Err(WireError::Locked)
        }
        fn read(&mut self, id: &ProtectorId) -> Result<Option<SecretBytes>, WireError> {
            Ok(self.0.get(id).map(|record| secret(record)))
        }
        fn create(&mut self, id: &ProtectorId, record: &[u8]) -> Result<(), WireError> {
            self.0.insert(*id, record.to_vec());
            Ok(())
        }
        fn delete(&mut self, id: &ProtectorId) -> Result<(), WireError> {
            self.0.remove(id);
            Ok(())
        }
    }

    fn exchange(requests: &[&[u8]]) -> Vec<Reply> {
        let mut input = Vec::new();
        for request in requests {
            write_frame(&mut input, request).unwrap();
        }
        let mut output = Vec::new();
        serve(&mut Cursor::new(input), &mut output, &mut Memory::default()).unwrap();
        let mut replies = Vec::new();
        let mut reader = Cursor::new(output);
        while let Some(frame) = read_frame(&mut reader).unwrap() {
            replies.push(decode_reply(&frame).unwrap());
        }
        replies
    }

    #[test]
    fn serve_dispatches_each_operation_and_reports_failures() {
        let request = |op| {
            encode_request(&Request {
                protector_id: ID,
                op,
            })
        };
        let replies = exchange(&[
            &request(Op::Read),
            &request(Op::Create(secret(b"r"))),
            &request(Op::Read),
            &request(Op::EnsureUnlocked),
            &request(Op::Delete),
            &request(Op::Read),
        ]);
        assert_eq!(
            replies,
            [
                Reply::NoRecord,
                Reply::Done,
                Reply::Record(secret(b"r")),
                Reply::Failed(WireError::Locked),
                Reply::Done,
                Reply::NoRecord,
            ]
        );
    }

    #[test]
    fn serve_stops_after_a_frame_it_cannot_understand() {
        let read = encode_request(&Request {
            protector_id: ID,
            op: Op::Read,
        });
        assert_eq!(
            exchange(&[b"junk", &read]),
            [Reply::Failed(WireError::Protocol)]
        );
    }
}
