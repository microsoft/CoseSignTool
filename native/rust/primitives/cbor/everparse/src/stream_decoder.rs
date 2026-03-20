// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming CBOR decoder for `Read + Seek` sources.
//!
//! [`EverparseStreamDecoder`] implements the [`CborStreamDecoder`] trait,
//! reading CBOR items from a buffered byte stream. It supports all CBOR
//! major types needed for COSE_Sign1 parsing and provides the critical
//! [`decode_bstr_header_offset`](CborStreamDecoder::decode_bstr_header_offset)
//! method for zero-copy payload access.
//!
//! This implementation reads CBOR wire format directly (it does not depend
//! on the EverParse verified parser, which requires in-memory slices).
//! The name reflects its home in the `cbor_primitives_everparse` crate.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

use cbor_primitives::{CborStreamDecoder, CborType};

use crate::EverparseError;

/// A streaming CBOR decoder that reads from a `Read + Seek` source.
///
/// Wraps the source in a [`BufReader`] for efficient small reads (peek,
/// initial-byte decoding) and tracks the current byte position.
///
/// # Example
///
/// ```ignore
/// use std::io::Cursor;
/// use cbor_primitives_everparse::EverparseStreamDecoder;
/// use cbor_primitives::CborStreamDecoder;
///
/// let data = vec![0x83, 0x01, 0x02, 0x03]; // CBOR array [1, 2, 3]
/// let mut decoder = EverparseStreamDecoder::new(Cursor::new(data));
/// let len = decoder.decode_array_len().unwrap();
/// assert_eq!(len, Some(3));
/// ```
pub struct EverparseStreamDecoder<R: Read + Seek> {
    reader: BufReader<R>,
    position: u64,
}

impl<R: Read + Seek> EverparseStreamDecoder<R> {
    /// Creates a new streaming decoder wrapping `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            position: 0,
        }
    }

    /// Consumes the decoder and returns the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Returns a mutable reference to the underlying buffered reader.
    pub fn reader_mut(&mut self) -> &mut BufReader<R> {
        &mut self.reader
    }

    /// Reads exactly `n` bytes, advancing position.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), EverparseError> {
        self.reader
            .read_exact(buf)
            .map_err(|e| EverparseError::InvalidData(format!("I/O error: {}", e)))?;
        self.position += buf.len() as u64;
        Ok(())
    }

    /// Reads the initial byte and splits it into major type and additional info.
    fn read_initial(&mut self) -> Result<(u8, u8), EverparseError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        let major: u8 = buf[0] >> 5;
        let additional: u8 = buf[0] & 0x1f;
        Ok((major, additional))
    }

    /// Decodes the argument following the initial byte.
    ///
    /// For additional info 0..=23 the value is inline; 24/25/26/27 read
    /// 1/2/4/8 additional bytes. 31 signals indefinite length (`u64::MAX`).
    fn decode_argument(&mut self, additional: u8) -> Result<u64, EverparseError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let mut buf = [0u8; 1];
                self.read_exact(&mut buf)?;
                Ok(buf[0] as u64)
            }
            25 => {
                let mut buf = [0u8; 2];
                self.read_exact(&mut buf)?;
                Ok(u16::from_be_bytes(buf) as u64)
            }
            26 => {
                let mut buf = [0u8; 4];
                self.read_exact(&mut buf)?;
                Ok(u32::from_be_bytes(buf) as u64)
            }
            27 => {
                let mut buf = [0u8; 8];
                self.read_exact(&mut buf)?;
                Ok(u64::from_be_bytes(buf))
            }
            31 => Ok(u64::MAX), // indefinite length sentinel
            _ => Err(EverparseError::InvalidData(
                "invalid additional info value".into(),
            )),
        }
    }

    /// Maps a CBOR major type + additional info to [`CborType`].
    fn major_to_cbor_type(major: u8, additional: u8) -> CborType {
        match major {
            0 => CborType::UnsignedInt,
            1 => CborType::NegativeInt,
            2 => CborType::ByteString,
            3 => CborType::TextString,
            4 => CborType::Array,
            5 => CborType::Map,
            6 => CborType::Tag,
            7 => match additional {
                20 | 21 => CborType::Bool,
                22 => CborType::Null,
                23 => CborType::Undefined,
                25 => CborType::Float16,
                26 => CborType::Float32,
                27 => CborType::Float64,
                31 => CborType::Break,
                _ => CborType::Simple,
            },
            _ => CborType::Simple, // unreachable for well-formed CBOR
        }
    }

    /// Skips over a single CBOR item in the stream (recursive for containers).
    fn skip_item(&mut self) -> Result<(), EverparseError> {
        let (major, additional) = self.read_initial()?;
        match major {
            // unsigned int / negative int — just consume the argument bytes
            0 | 1 => {
                let _ = self.decode_argument(additional)?;
                Ok(())
            }
            // byte string / text string — consume argument + content bytes
            2 | 3 => {
                let len = self.decode_argument(additional)?;
                if len == u64::MAX {
                    // indefinite length: skip chunks until break
                    loop {
                        let peeked = self.peek_byte()?;
                        if peeked == 0xff {
                            // consume break
                            let mut brk = [0u8; 1];
                            self.read_exact(&mut brk)?;
                            break;
                        }
                        self.skip_item()?;
                    }
                } else {
                    self.skip_bytes(len)?;
                }
                Ok(())
            }
            // array
            4 => {
                let len = self.decode_argument(additional)?;
                if len == u64::MAX {
                    loop {
                        let peeked = self.peek_byte()?;
                        if peeked == 0xff {
                            let mut brk = [0u8; 1];
                            self.read_exact(&mut brk)?;
                            break;
                        }
                        self.skip_item()?;
                    }
                } else {
                    for _ in 0..len {
                        self.skip_item()?;
                    }
                }
                Ok(())
            }
            // map
            5 => {
                let len = self.decode_argument(additional)?;
                if len == u64::MAX {
                    loop {
                        let peeked = self.peek_byte()?;
                        if peeked == 0xff {
                            let mut brk = [0u8; 1];
                            self.read_exact(&mut brk)?;
                            break;
                        }
                        self.skip_item()?; // key
                        self.skip_item()?; // value
                    }
                } else {
                    for _ in 0..len {
                        self.skip_item()?; // key
                        self.skip_item()?; // value
                    }
                }
                Ok(())
            }
            // tag — skip the argument then skip the tagged item
            6 => {
                let _ = self.decode_argument(additional)?;
                self.skip_item()
            }
            // simple / float
            7 => {
                match additional {
                    0..=23 => Ok(()), // simple value already consumed
                    24 => {
                        let mut buf = [0u8; 1];
                        self.read_exact(&mut buf)?;
                        Ok(())
                    }
                    25 => {
                        let mut buf = [0u8; 2];
                        self.read_exact(&mut buf)?;
                        Ok(())
                    }
                    26 => {
                        let mut buf = [0u8; 4];
                        self.read_exact(&mut buf)?;
                        Ok(())
                    }
                    27 => {
                        let mut buf = [0u8; 8];
                        self.read_exact(&mut buf)?;
                        Ok(())
                    }
                    31 => Ok(()), // break — already consumed
                    _ => Err(EverparseError::InvalidData(
                        "invalid simple value encoding".into(),
                    )),
                }
            }
            _ => Err(EverparseError::InvalidData(
                "invalid CBOR major type".into(),
            )),
        }
    }

    /// Peeks at the next byte without consuming it.
    fn peek_byte(&mut self) -> Result<u8, EverparseError> {
        let buf = self
            .reader
            .fill_buf()
            .map_err(|e| EverparseError::InvalidData(format!("I/O error: {}", e)))?;
        if buf.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }
        Ok(buf[0])
    }

    /// Skips `len` bytes by seeking forward.
    fn skip_bytes(&mut self, len: u64) -> Result<(), EverparseError> {
        // Discard any buffered data first so the seek is accurate.
        let buffered = self.reader.buffer().len() as u64;
        if len <= buffered {
            self.reader.consume(len as usize);
        } else {
            let remaining_after_buffer: i64 = (len - buffered) as i64;
            self.reader.consume(buffered as usize);
            self.reader
                .seek(SeekFrom::Current(remaining_after_buffer))
                .map_err(|e| EverparseError::InvalidData(format!("I/O seek error: {}", e)))?;
        }
        self.position += len;
        Ok(())
    }

    /// Advances the stream by `n` bytes, updating the tracked position.
    ///
    /// This is useful after [`CborStreamDecoder::decode_bstr_header_offset`] to
    /// skip over the content bytes of a byte string without reading them.
    pub fn skip_n_bytes(&mut self, n: u64) -> Result<(), EverparseError> {
        self.skip_bytes(n)
    }

    /// Reads the next complete CBOR item and returns its raw bytes as a `Vec<u8>`.
    ///
    /// This is the streaming equivalent of [`CborDecoder::decode_raw`]. It first
    /// skips the item to determine its byte length, then seeks back and reads
    /// the raw bytes.
    pub fn decode_raw_owned(&mut self) -> Result<Vec<u8>, EverparseError> {
        let start = self.position;
        self.skip_item()?;
        let end = self.position;
        let len: usize = (end - start) as usize;

        // Seek back in the underlying reader to re-read the raw bytes.
        // BufReader::seek discards its internal buffer.
        self.reader
            .seek(SeekFrom::Start(start))
            .map_err(|e| EverparseError::InvalidData(format!("I/O seek error: {}", e)))?;
        let mut buf = vec![0u8; len];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| EverparseError::InvalidData(format!("I/O error: {}", e)))?;

        // Re-seek forward to the position after the item.
        self.reader
            .seek(SeekFrom::Start(end))
            .map_err(|e| EverparseError::InvalidData(format!("I/O seek error: {}", e)))?;

        Ok(buf)
    }
}

impl<R: Read + Seek> CborStreamDecoder for EverparseStreamDecoder<R> {
    type Error = EverparseError;

    fn peek_type(&mut self) -> Result<CborType, Self::Error> {
        let byte = self.peek_byte()?;
        let major: u8 = byte >> 5;
        let additional: u8 = byte & 0x1f;
        Ok(Self::major_to_cbor_type(major, additional))
    }

    fn decode_u64(&mut self) -> Result<u64, Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 0 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::UnsignedInt,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        self.decode_argument(additional)
    }

    fn decode_i64(&mut self) -> Result<i64, Self::Error> {
        let (major, additional) = self.read_initial()?;
        match major {
            0 => {
                let val = self.decode_argument(additional)?;
                i64::try_from(val).map_err(|_| EverparseError::Overflow)
            }
            1 => {
                let val = self.decode_argument(additional)?;
                if val <= i64::MAX as u64 {
                    Ok(-1 - val as i64)
                } else {
                    Err(EverparseError::Overflow)
                }
            }
            _ => Err(EverparseError::UnexpectedType {
                expected: CborType::UnsignedInt,
                found: Self::major_to_cbor_type(major, additional),
            }),
        }
    }

    fn decode_bstr_owned(&mut self) -> Result<Vec<u8>, Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 2 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::ByteString,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        let len = self.decode_argument(additional)?;
        if len == u64::MAX {
            return Err(EverparseError::NotSupported(
                "indefinite-length byte strings".into(),
            ));
        }
        let len_usize: usize = usize::try_from(len).map_err(|_| EverparseError::Overflow)?;
        let mut buf = vec![0u8; len_usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn decode_bstr_header_offset(&mut self) -> Result<(u64, u64), Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 2 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::ByteString,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        let len = self.decode_argument(additional)?;
        if len == u64::MAX {
            return Err(EverparseError::NotSupported(
                "indefinite-length byte strings".into(),
            ));
        }
        // position is now at the start of the content bytes
        Ok((self.position, len))
    }

    fn decode_tstr_owned(&mut self) -> Result<String, Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 3 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::TextString,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        let len = self.decode_argument(additional)?;
        if len == u64::MAX {
            return Err(EverparseError::NotSupported(
                "indefinite-length text strings".into(),
            ));
        }
        let len_usize: usize = usize::try_from(len).map_err(|_| EverparseError::Overflow)?;
        let mut buf = vec![0u8; len_usize];
        self.read_exact(&mut buf)?;
        String::from_utf8(buf).map_err(|_| EverparseError::InvalidUtf8)
    }

    fn decode_array_len(&mut self) -> Result<Option<usize>, Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 4 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Array,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        let len = self.decode_argument(additional)?;
        if len == u64::MAX {
            Ok(None)
        } else {
            let len_usize: usize = usize::try_from(len).map_err(|_| EverparseError::Overflow)?;
            Ok(Some(len_usize))
        }
    }

    fn decode_map_len(&mut self) -> Result<Option<usize>, Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 5 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Map,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        let len = self.decode_argument(additional)?;
        if len == u64::MAX {
            Ok(None)
        } else {
            let len_usize: usize = usize::try_from(len).map_err(|_| EverparseError::Overflow)?;
            Ok(Some(len_usize))
        }
    }

    fn decode_tag(&mut self) -> Result<u64, Self::Error> {
        let (major, additional) = self.read_initial()?;
        if major != 6 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Tag,
                found: Self::major_to_cbor_type(major, additional),
            });
        }
        self.decode_argument(additional)
    }

    fn decode_bool(&mut self) -> Result<bool, Self::Error> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        match buf[0] {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            other => {
                let major: u8 = other >> 5;
                let additional: u8 = other & 0x1f;
                Err(EverparseError::UnexpectedType {
                    expected: CborType::Bool,
                    found: Self::major_to_cbor_type(major, additional),
                })
            }
        }
    }

    fn decode_null(&mut self) -> Result<(), Self::Error> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        if buf[0] == 0xf6 {
            Ok(())
        } else {
            let major: u8 = buf[0] >> 5;
            let additional: u8 = buf[0] & 0x1f;
            Err(EverparseError::UnexpectedType {
                expected: CborType::Null,
                found: Self::major_to_cbor_type(major, additional),
            })
        }
    }

    fn is_null(&mut self) -> Result<bool, Self::Error> {
        let byte = self.peek_byte()?;
        Ok(byte == 0xf6)
    }

    fn skip(&mut self) -> Result<(), Self::Error> {
        self.skip_item()
    }

    fn position(&self) -> u64 {
        self.position
    }
}
