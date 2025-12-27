// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{Read, Seek};

/// Helper trait for `Read + Seek` as a single trait object.
pub trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}
