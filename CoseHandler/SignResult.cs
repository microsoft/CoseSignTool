// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

using System;

public class SignResult(ReadOnlyMemory<byte>? signedBytes = null)
{
    public ReadOnlyMemory<byte>? SignedBytes { get; } = signedBytes;
    public bool IsSuccess { get; internal set; }
    public Exception Exception { get; internal set; }
}