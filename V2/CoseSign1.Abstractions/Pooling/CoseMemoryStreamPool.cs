// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Pooling;

using System;
using Cose.Abstractions;
using Microsoft.IO;

/// <summary>
/// String constants for <see cref="CoseMemoryStreamPool"/>.
/// </summary>
internal static class ClassStrings
{
    public static readonly string ErrorPoolAlreadyInitialized =
        "CoseMemoryStreamPool has already been initialized. Call Configure() before any signing or validation operations.";
}

/// <summary>
/// Shared pooled MemoryStream provider that avoids Large Object Heap pressure.
/// </summary>
/// <remarks>
/// <para>
/// Uses a single <see cref="RecyclableMemoryStreamManager"/> shared across all
/// CoseSign1 components (signing, validation, certificates, CLI). This prevents
/// pool fragmentation from multiple independent managers.
/// </para>
/// <para>
/// <b>Adaptive defaults:</b> If not explicitly configured via <see cref="Configure"/>,
/// pool sizes auto-scale based on available system memory — safe in both 256MB
/// containers and 64GB servers.
/// </para>
/// <para>
/// <b>Thread-safe:</b> <see cref="RecyclableMemoryStreamManager"/> is thread-safe.
/// </para>
/// </remarks>
public static class CoseMemoryStreamPool
{
    private static volatile RecyclableMemoryStreamManager? s_manager;
    private static readonly object s_lock = new();

    /// <summary>
    /// Gets the shared <see cref="RecyclableMemoryStreamManager"/>.
    /// Auto-initializes with adaptive defaults on first access if not configured.
    /// </summary>
    public static RecyclableMemoryStreamManager Manager
    {
        get
        {
            if (s_manager is not null)
            {
                return s_manager;
            }

            lock (s_lock)
            {
                s_manager ??= CreateManager(new MemoryStreamPoolOptions());
            }

            return s_manager;
        }
    }

    /// <summary>
    /// Configures the shared pool with explicit options. Must be called before
    /// any <see cref="GetStream()"/> calls (typically at application startup).
    /// </summary>
    /// <param name="options">Pool configuration. Null values auto-size from available memory.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the pool has already been initialized (streams already dispensed).
    /// Call this method early in application startup before any signing/validation.
    /// </exception>
    public static void Configure(MemoryStreamPoolOptions options)
    {
        Guard.ThrowIfNull(options);

        lock (s_lock)
        {
            if (s_manager is not null)
            {
                throw new InvalidOperationException(ClassStrings.ErrorPoolAlreadyInitialized);
            }

            s_manager = CreateManager(options);
        }
    }

    /// <summary>
    /// Gets a pooled MemoryStream.
    /// </summary>
    /// <returns>A pooled <see cref="MemoryStream"/> instance.</returns>
    public static MemoryStream GetStream() => Manager.GetStream();

    /// <summary>
    /// Gets a pooled MemoryStream with a diagnostic tag.
    /// </summary>
    /// <param name="tag">Diagnostic tag for identifying the stream's purpose.</param>
    /// <returns>A pooled <see cref="MemoryStream"/> instance.</returns>
    public static MemoryStream GetStream(string tag) => Manager.GetStream(tag);

    /// <summary>
    /// Gets a pooled MemoryStream pre-loaded with the given buffer.
    /// </summary>
    /// <param name="buffer">Initial data to write into the stream.</param>
    /// <returns>A pooled <see cref="MemoryStream"/> pre-loaded with <paramref name="buffer"/>.</returns>
    public static MemoryStream GetStream(byte[] buffer) => Manager.GetStream(buffer);

    /// <summary>
    /// Resets the pool for testing purposes. Not intended for production use.
    /// </summary>
    internal static void ResetForTesting()
    {
        lock (s_lock)
        {
            s_manager = null;
        }
    }

    private static RecyclableMemoryStreamManager CreateManager(MemoryStreamPoolOptions options)
    {
        long availableMemory = GetAvailableMemoryBytes();

        // Auto-size: 2% of available for small pool, 4% for large pool
        long smallPoolMax = options.MaximumSmallPoolFreeBytes
            ?? Clamp((long)(availableMemory * 0.02), 4L * 1024 * 1024, 128L * 1024 * 1024);

        long largePoolMax = options.MaximumLargePoolFreeBytes
            ?? Clamp((long)(availableMemory * 0.04), 8L * 1024 * 1024, 512L * 1024 * 1024);

        return new RecyclableMemoryStreamManager(new RecyclableMemoryStreamManager.Options
        {
            BlockSize = options.BlockSize,
            LargeBufferMultiple = options.LargeBufferMultiple,
            MaximumBufferSize = options.MaximumBufferSize,
            MaximumSmallPoolFreeBytes = smallPoolMax,
            MaximumLargePoolFreeBytes = largePoolMax,
        });
    }

    private static long GetAvailableMemoryBytes()
    {
        try
        {
#if NET5_0_OR_GREATER
            GCMemoryInfo gcInfo = GC.GetGCMemoryInfo();
            // Use total available memory (respects container cgroup limits)
            long total = gcInfo.TotalAvailableMemoryBytes;
            if (total > 0)
            {
                return total;
            }
#endif
            // Fallback: use GC heap size as a rough proxy
            // In containers this reflects the cgroup memory limit
            return Environment.WorkingSet > 0
                ? Environment.WorkingSet * 4 // Rough: assume working set is ~25% of limit
                : 512L * 1024 * 1024; // Conservative default: assume 512MB
        }
        catch
        {
            // Absolute fallback: assume constrained environment
            return 512L * 1024 * 1024;
        }
    }

    private static long Clamp(long value, long min, long max) =>
        value < min ? min : value > max ? max : value;
}
