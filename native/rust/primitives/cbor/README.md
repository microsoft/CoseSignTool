# cbor_primitives

A zero-dependency trait crate that defines abstractions for CBOR encoding/decoding, allowing pluggable implementations per [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949).

## Overview

This crate provides trait definitions for CBOR operations without any concrete implementations. It enables:

- **Pluggable CBOR backends**: Switch between different CBOR libraries (EverParse, ciborium, etc.) without changing application code
- **Zero dependencies**: The trait crate itself has no runtime dependencies
- **Complete RFC 8949 coverage**: Supports all CBOR data types including indefinite-length items

## Types

### `CborType`

Enum representing all CBOR data types:

- `UnsignedInt` - Major type 0
- `NegativeInt` - Major type 1
- `ByteString` - Major type 2
- `TextString` - Major type 3
- `Array` - Major type 4
- `Map` - Major type 5
- `Tag` - Major type 6
- `Simple`, `Float16`, `Float32`, `Float64`, `Bool`, `Null`, `Undefined`, `Break` - Major type 7

### `CborSimple`

Enum for CBOR simple values: `False`, `True`, `Null`, `Undefined`, `Unassigned(u8)`

### `CborError`

Common error type with variants for typical CBOR errors:
- `UnexpectedType { expected, found }`
- `UnexpectedEof`
- `InvalidUtf8`
- `Overflow`
- `InvalidSimple(u8)`
- `Custom(String)`

## Traits

### `CborEncoder`

Trait for encoding CBOR data. Implementors must provide methods for all CBOR types:

```rust
pub trait CborEncoder {
    type Error: std::error::Error + Send + Sync + 'static;
    
    // Unsigned integers
    fn encode_u8(&mut self, value: u8) -> Result<(), Self::Error>;
    fn encode_u16(&mut self, value: u16) -> Result<(), Self::Error>;
    fn encode_u32(&mut self, value: u32) -> Result<(), Self::Error>;
    fn encode_u64(&mut self, value: u64) -> Result<(), Self::Error>;
    
    // Signed integers
    fn encode_i8(&mut self, value: i8) -> Result<(), Self::Error>;
    fn encode_i16(&mut self, value: i16) -> Result<(), Self::Error>;
    fn encode_i32(&mut self, value: i32) -> Result<(), Self::Error>;
    fn encode_i64(&mut self, value: i64) -> Result<(), Self::Error>;
    fn encode_i128(&mut self, value: i128) -> Result<(), Self::Error>;
    
    // Byte strings
    fn encode_bstr(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn encode_bstr_header(&mut self, len: u64) -> Result<(), Self::Error>;
    fn encode_bstr_indefinite_begin(&mut self) -> Result<(), Self::Error>;
    
    // Text strings
    fn encode_tstr(&mut self, data: &str) -> Result<(), Self::Error>;
    fn encode_tstr_header(&mut self, len: u64) -> Result<(), Self::Error>;
    fn encode_tstr_indefinite_begin(&mut self) -> Result<(), Self::Error>;
    
    // Collections
    fn encode_array(&mut self, len: usize) -> Result<(), Self::Error>;
    fn encode_array_indefinite_begin(&mut self) -> Result<(), Self::Error>;
    fn encode_map(&mut self, len: usize) -> Result<(), Self::Error>;
    fn encode_map_indefinite_begin(&mut self) -> Result<(), Self::Error>;
    
    // Tags and simple values
    fn encode_tag(&mut self, tag: u64) -> Result<(), Self::Error>;
    fn encode_bool(&mut self, value: bool) -> Result<(), Self::Error>;
    fn encode_null(&mut self) -> Result<(), Self::Error>;
    fn encode_undefined(&mut self) -> Result<(), Self::Error>;
    fn encode_simple(&mut self, value: CborSimple) -> Result<(), Self::Error>;
    
    // Floats
    fn encode_f16(&mut self, value: f32) -> Result<(), Self::Error>;
    fn encode_f32(&mut self, value: f32) -> Result<(), Self::Error>;
    fn encode_f64(&mut self, value: f64) -> Result<(), Self::Error>;
    
    // Control
    fn encode_break(&mut self) -> Result<(), Self::Error>;
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
    
    // Output
    fn into_bytes(self) -> Vec<u8>;
    fn as_bytes(&self) -> &[u8];
}
```

### `CborDecoder`

Trait for decoding CBOR data. Implementors must provide methods for all CBOR types:

```rust
pub trait CborDecoder<'a> {
    type Error: std::error::Error + Send + Sync + 'static;
    
    // Type inspection
    fn peek_type(&mut self) -> Result<CborType, Self::Error>;
    fn is_break(&mut self) -> Result<bool, Self::Error>;
    fn is_null(&mut self) -> Result<bool, Self::Error>;
    fn is_undefined(&mut self) -> Result<bool, Self::Error>;
    
    // Decode methods for all types...
    
    // Navigation
    fn skip(&mut self) -> Result<(), Self::Error>;
    fn remaining(&self) -> &'a [u8];
    fn position(&self) -> usize;
}
```

### `CborProvider`

Factory trait for creating encoders and decoders:

```rust
pub trait CborProvider: Send + Sync + Clone + 'static {
    type Encoder: CborEncoder;
    type Decoder<'a>: CborDecoder<'a>;
    type Error: std::error::Error + Send + Sync + 'static;
    
    fn encoder(&self) -> Self::Encoder;
    fn encoder_with_capacity(&self, capacity: usize) -> Self::Encoder;
    fn decoder<'a>(&self, data: &'a [u8]) -> Self::Decoder<'a>;
}
```

## Implementing a Provider

To implement a CBOR provider, create types that implement `CborEncoder` and `CborDecoder`, then implement `CborProvider` to create them:

```rust
use cbor_primitives::{CborEncoder, CborDecoder, CborProvider, CborType, CborSimple};

struct MyEncoder { /* ... */ }
struct MyDecoder<'a> { /* ... */ }
struct MyError(String);

impl CborEncoder for MyEncoder { /* ... */ }
impl<'a> CborDecoder<'a> for MyDecoder<'a> { /* ... */ }

#[derive(Clone)]
struct MyProvider;

impl CborProvider for MyProvider {
    type Encoder = MyEncoder;
    type Decoder<'a> = MyDecoder<'a>;
    type Error = MyError;
    
    fn encoder(&self) -> Self::Encoder { MyEncoder::new() }
    fn encoder_with_capacity(&self, cap: usize) -> Self::Encoder { MyEncoder::with_capacity(cap) }
    fn decoder<'a>(&self, data: &'a [u8]) -> Self::Decoder<'a> { MyDecoder::new(data) }
}
```

## License

MIT
