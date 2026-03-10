// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.IO;

using CoseSign1.Abstractions;

/// <summary>
/// A read-only stream wrapper that implements a timeout for initial data availability.
/// If no data is received within the specified timeout, reads will return 0 bytes (EOF).
/// This is useful for stdin where we want to detect if data is being piped vs. no input.
/// </summary>
public sealed class TimeoutReadStream : Stream
{
    private readonly Stream InnerStream;
    private readonly TimeSpan InitialTimeout;
    private readonly CancellationTokenSource TimeoutCts;
    private bool ReceivedData;
    private bool IsTimedOut;
    private readonly object Lock = new();

    /// <summary>
    /// Creates a new TimeoutReadStream wrapping the specified stream.
    /// </summary>
    /// <param name="innerStream">The stream to wrap (typically stdin).</param>
    /// <param name="initialTimeout">
    /// How long to wait for the first bytes before considering stdin empty.
    /// Default is 2 seconds.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="innerStream"/> is <see langword="null"/>.</exception>
    public TimeoutReadStream(Stream innerStream, TimeSpan? initialTimeout = null)
    {
        Guard.ThrowIfNull(innerStream);
        InnerStream = innerStream;
        InitialTimeout = initialTimeout ?? TimeSpan.FromSeconds(2);
        TimeoutCts = new CancellationTokenSource();
        ReceivedData = false;
        IsTimedOut = false;
    }

    /// <summary>
    /// Gets whether data was received before timeout.
    /// </summary>
    public bool HasReceivedData
    {
        get { lock (Lock) { return ReceivedData; } }
    }

    /// <summary>
    /// Gets whether the initial read timed out (no data received).
    /// </summary>
    public bool TimedOut
    {
        get { lock (Lock) { return IsTimedOut; } }
    }

    /// <inheritdoc/>
    public override bool CanRead => true;

    /// <inheritdoc/>
    public override bool CanSeek => false;

    /// <inheritdoc/>
    public override bool CanWrite => false;

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">This stream does not support seeking.</exception>
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">This stream does not support seeking.</exception>
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
#if NETSTANDARD2_0
        // netstandard2.0 doesn't have Memory<T> overload, implement directly here
        // If we already timed out, return EOF
        lock (Lock)
        {
            if (IsTimedOut)
            {
                return 0;
            }
        }

        // If we haven't received data yet, apply the initial timeout
        bool needsTimeout;
        lock (Lock)
        {
            needsTimeout = !ReceivedData;
        }

        if (needsTimeout)
        {
            try
            {
                // Create a combined cancellation token with our timeout
                using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, TimeoutCts.Token);

                // Start the timeout
                TimeoutCts.CancelAfter(InitialTimeout);

                // Try to read with timeout
                int bytesRead = await InnerStream.ReadAsync(buffer, offset, count, linkedCts.Token).ConfigureAwait(false);

                if (bytesRead > 0)
                {
                    lock (Lock)
                    {
                        ReceivedData = true;
                    }
                }

                return bytesRead;
            }
            catch (OperationCanceledException) when (TimeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                // Our timeout fired, not the external cancellation
                lock (Lock)
                {
                    IsTimedOut = true;
                }
                return 0; // Return EOF to signal no data
            }
        }

        // Already received data, just pass through
        return await InnerStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
#else
        return await ReadAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
#endif
    }

#if !NETSTANDARD2_0
    /// <inheritdoc/>
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // If we already timed out, return EOF
        lock (Lock)
        {
            if (IsTimedOut)
            {
                return 0;
            }
        }

        // If we haven't received data yet, apply the initial timeout
        bool needsTimeout;
        lock (Lock)
        {
            needsTimeout = !ReceivedData;
        }

        if (needsTimeout)
        {
            try
            {
                // Create a combined cancellation token with our timeout
                using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, TimeoutCts.Token);

                // Start the timeout
                TimeoutCts.CancelAfter(InitialTimeout);

                // Try to read with timeout
                int bytesRead = await InnerStream.ReadAsync(buffer, linkedCts.Token).ConfigureAwait(false);

                if (bytesRead > 0)
                {
                    lock (Lock)
                    {
                        ReceivedData = true;
                    }
                }

                return bytesRead;
            }
            catch (OperationCanceledException) when (TimeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                // Our timeout fired, not the external cancellation
                lock (Lock)
                {
                    IsTimedOut = true;
                }
                return 0; // Return EOF to signal no data
            }
        }

        // Already received data, just pass through
        return await InnerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }
#endif

    /// <inheritdoc/>
    public override void Flush()
    {
        InnerStream.Flush();
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">This stream does not support seeking.</exception>
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">This stream does not support writing.</exception>
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">This stream does not support writing.</exception>
    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            TimeoutCts.Dispose();
            // Don't dispose the inner stream - we don't own it (it's stdin)
        }
        base.Dispose(disposing);
    }
}
