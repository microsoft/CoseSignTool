// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

using Microsoft.IO;

/// <summary>
/// Provides pooled MemoryStream instances to avoid Large Object Heap allocations.
/// </summary>
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
internal static class MemoryStreamPool
{
    private static readonly RecyclableMemoryStreamManager Manager = new(new RecyclableMemoryStreamManager.Options
    {
        BlockSize = 128 * 1024,                // 128KB blocks
        LargeBufferMultiple = 1024 * 1024,     // 1MB large buffer increments
        MaximumBufferSize = 16 * 1024 * 1024,  // 16MB max single buffer
        MaximumSmallPoolFreeBytes = 8 * 1024 * 1024,   // 8MB max small pool
        MaximumLargePoolFreeBytes = 16 * 1024 * 1024,  // 16MB max large pool
    });

    public static MemoryStream GetStream() => Manager.GetStream();
    public static MemoryStream GetStream(string tag) => Manager.GetStream(tag);
}