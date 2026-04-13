// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Pooling;

/// <summary>
/// Configuration options for the shared <see cref="CoseMemoryStreamPool"/>.
/// </summary>
/// <remarks>
/// If not explicitly configured, the pool auto-sizes based on available system memory:
/// <list type="bullet">
///   <item>Small pool: 2% of available memory (min 4MB, max 128MB)</item>
///   <item>Large pool: 4% of available memory (min 8MB, max 512MB)</item>
/// </list>
/// This ensures the pool works in both 256MB containers and 64GB servers
/// without manual tuning.
/// </remarks>
public sealed class MemoryStreamPoolOptions
{
    /// <summary>
    /// Size of each small buffer block. Default: 128KB.
    /// </summary>
    public int BlockSize { get; set; } = 128 * 1024;

    /// <summary>
    /// Large buffer allocation granularity. Default: 1MB.
    /// </summary>
    public int LargeBufferMultiple { get; set; } = 1024 * 1024;

    /// <summary>
    /// Maximum size of a single buffer before it is not pooled. Default: 16MB.
    /// </summary>
    public int MaximumBufferSize { get; set; } = 16 * 1024 * 1024;

    /// <summary>
    /// Maximum bytes retained in the small buffer pool.
    /// If null, auto-sized to 2% of available memory (clamped to 4MB–128MB).
    /// Set to 0 to disable pooling of small buffers.
    /// </summary>
    public long? MaximumSmallPoolFreeBytes { get; set; }

    /// <summary>
    /// Maximum bytes retained in the large buffer pool.
    /// If null, auto-sized to 4% of available memory (clamped to 8MB–512MB).
    /// Set to 0 to disable pooling of large buffers.
    /// </summary>
    public long? MaximumLargePoolFreeBytes { get; set; }
}
