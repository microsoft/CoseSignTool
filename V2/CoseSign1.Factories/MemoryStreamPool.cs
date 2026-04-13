// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories;

using CoseSign1.Abstractions.Pooling;

/// <summary>
/// Provides pooled MemoryStream instances via the shared <see cref="CoseMemoryStreamPool"/>.
/// </summary>
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
internal static class MemoryStreamPool
{
    public static MemoryStream GetStream() => CoseMemoryStreamPool.GetStream();
    public static MemoryStream GetStream(string tag) => CoseMemoryStreamPool.GetStream(tag);
    public static MemoryStream GetStream(byte[] buffer) => CoseMemoryStreamPool.GetStream(buffer);
}