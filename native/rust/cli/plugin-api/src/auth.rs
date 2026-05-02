// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Authentication helpers for plugin IPC.

/// Length of the auth key in bytes.
pub const AUTH_KEY_LENGTH: usize = 32;

/// Environment variable name for the auth key passed from host to plugin.
pub const AUTH_KEY_ENV_VAR: &str = "COSESIGNTOOL_PLUGIN_AUTH_KEY";

/// Errors that can occur while handling plugin auth keys.
#[derive(Debug)]
pub enum AuthError {
    /// The auth key environment variable was missing or invalid.
    EnvironmentVariable(String),
    /// The auth key hex string did not have the expected length.
    InvalidHexLength {
        /// Expected number of hex characters.
        expected: usize,
        /// Actual number of hex characters.
        actual: usize,
    },
    /// The auth key hex string contained an invalid character.
    InvalidHexCharacter {
        /// Zero-based character index.
        index: usize,
        /// The invalid character.
        value: char,
    },
    /// Random generation or I/O failed.
    Io(std::io::Error),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvironmentVariable(message) => write!(f, "{}", message),
            Self::InvalidHexLength { expected, actual } => write!(
                f,
                "auth key hex must be {} characters, got {}",
                expected, actual
            ),
            Self::InvalidHexCharacter { index, value } => {
                write!(
                    f,
                    "auth key hex contains invalid character '{}' at index {}",
                    value, index
                )
            }
            Self::Io(error) => write!(f, "auth key I/O failed: {}", error),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AuthError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Generate a cryptographically random auth key.
pub fn generate_auth_key() -> [u8; AUTH_KEY_LENGTH] {
    let mut key = [0u8; AUTH_KEY_LENGTH];
    if let Err(error) = fill_random(&mut key) {
        panic!("Failed to generate plugin auth key: {}", error);
    }
    key
}

/// Encode auth key bytes as a lowercase hex string.
pub fn auth_key_to_hex(key: &[u8; AUTH_KEY_LENGTH]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut hex = String::with_capacity(AUTH_KEY_LENGTH * 2);
    for byte in key {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Decode a lowercase or uppercase hex string into auth key bytes.
pub fn auth_key_from_hex(hex: &str) -> Result<[u8; AUTH_KEY_LENGTH], AuthError> {
    let expected_length = AUTH_KEY_LENGTH * 2;
    if hex.len() != expected_length {
        return Err(AuthError::InvalidHexLength {
            expected: expected_length,
            actual: hex.len(),
        });
    }

    let bytes = hex.as_bytes();
    let mut key = [0u8; AUTH_KEY_LENGTH];
    for index in 0..AUTH_KEY_LENGTH {
        let high = decode_hex_nibble(bytes[index * 2], index * 2)?;
        let low = decode_hex_nibble(bytes[(index * 2) + 1], (index * 2) + 1)?;
        key[index] = (high << 4) | low;
    }

    Ok(key)
}

/// Compare two byte slices in constant time.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }

    difference == 0
}

/// Read the auth key from the environment and clear it immediately.
pub fn read_and_clear_auth_key() -> Result<[u8; AUTH_KEY_LENGTH], AuthError> {
    let value = std::env::var(AUTH_KEY_ENV_VAR).map_err(|error| {
        AuthError::EnvironmentVariable(format!(
            "{} environment variable is not available: {}",
            AUTH_KEY_ENV_VAR, error
        ))
    })?;

    std::env::remove_var(AUTH_KEY_ENV_VAR);
    auth_key_from_hex(value.as_str())
}

#[cfg(unix)]
fn fill_random(buffer: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;

    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(buffer)
}

#[cfg(windows)]
fn fill_random(buffer: &mut [u8]) -> std::io::Result<()> {
    use std::ffi::c_void;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            output: *mut u8,
            output_length: u32,
            flags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    let output_length = u32::try_from(buffer.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth key buffer is too large for BCryptGenRandom",
        )
    })?;

    // SAFETY: `buffer` is a valid writable slice for `output_length` bytes, and
    // passing a null algorithm handle is supported with
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            output_length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status == 0 {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "BCryptGenRandom failed with status {}",
        status
    )))
}

fn decode_hex_nibble(value: u8, index: usize) -> Result<u8, AuthError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AuthError::InvalidHexCharacter {
            index,
            value: char::from(value),
        }),
    }
}
