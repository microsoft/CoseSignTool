// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.IO;

namespace CoseSignTool.Tests.IO;

[TestFixture]
public class TimeoutReadStreamTests
{
    [Test]
    public async Task ReadAsync_WithDataAvailable_ReturnsData()
    {
        // Arrange
        var testData = new byte[] { 1, 2, 3, 4, 5 };
        using var innerStream = new MemoryStream(testData);
        using var timeoutStream = new TimeoutReadStream(innerStream, TimeSpan.FromSeconds(5));

        // Act
        var buffer = new byte[10];
        var bytesRead = await timeoutStream.ReadAsync(buffer, 0, buffer.Length);

        // Assert
        Assert.That(bytesRead, Is.EqualTo(5));
        Assert.That(buffer[..5], Is.EqualTo(testData));
        Assert.That(timeoutStream.HasReceivedData, Is.True);
        Assert.That(timeoutStream.TimedOut, Is.False);
    }

    [Test]
    public void Read_WithDataAvailable_ReturnsData()
    {
        // Arrange
        var testData = new byte[] { 1, 2, 3, 4, 5 };
        using var innerStream = new MemoryStream(testData);
        using var timeoutStream = new TimeoutReadStream(innerStream, TimeSpan.FromSeconds(5));

        // Act
        var buffer = new byte[10];
        var bytesRead = timeoutStream.Read(buffer, 0, buffer.Length);

        // Assert
        Assert.That(bytesRead, Is.EqualTo(5));
        Assert.That(buffer[..5], Is.EqualTo(testData));
        Assert.That(timeoutStream.HasReceivedData, Is.True);
        Assert.That(timeoutStream.TimedOut, Is.False);
    }

    [Test]
    public async Task ReadAsync_WithEmptyStreamAndTimeout_ReturnsEOFAfterTimeout()
    {
        // Arrange - Use a stream that blocks on read (simulating no data)
        using var blockingStream = new BlockingStream();
        using var timeoutStream = new TimeoutReadStream(blockingStream, TimeSpan.FromMilliseconds(100));

        // Act
        var buffer = new byte[10];
        var bytesRead = await timeoutStream.ReadAsync(buffer, 0, buffer.Length);

        // Assert
        Assert.That(bytesRead, Is.EqualTo(0), "Should return 0 (EOF) after timeout");
        Assert.That(timeoutStream.TimedOut, Is.True, "Should indicate timeout occurred");
        Assert.That(timeoutStream.HasReceivedData, Is.False, "Should indicate no data received");
    }

    [Test]
    public async Task ReadAsync_AfterTimeout_SubsequentReadsReturnEOF()
    {
        // Arrange
        using var blockingStream = new BlockingStream();
        using var timeoutStream = new TimeoutReadStream(blockingStream, TimeSpan.FromMilliseconds(100));

        // Act - First read should timeout
        var buffer = new byte[10];
        var bytesRead1 = await timeoutStream.ReadAsync(buffer, 0, buffer.Length);
        var bytesRead2 = await timeoutStream.ReadAsync(buffer, 0, buffer.Length);

        // Assert
        Assert.That(bytesRead1, Is.EqualTo(0));
        Assert.That(bytesRead2, Is.EqualTo(0));
        Assert.That(timeoutStream.TimedOut, Is.True);
    }

    [Test]
    public async Task ReadAsync_WithLargeData_ReadsAllData()
    {
        // Arrange
        var testData = new byte[10000];
        new Random(42).NextBytes(testData);
        using var innerStream = new MemoryStream(testData);
        using var timeoutStream = new TimeoutReadStream(innerStream, TimeSpan.FromSeconds(5));
        using var resultStream = new MemoryStream();

        // Act
        await timeoutStream.CopyToAsync(resultStream);

        // Assert
        Assert.That(resultStream.ToArray(), Is.EqualTo(testData));
        Assert.That(timeoutStream.HasReceivedData, Is.True);
        Assert.That(timeoutStream.TimedOut, Is.False);
    }

    [Test]
    public void CanRead_ReturnsTrue()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.That(timeoutStream.CanRead, Is.True);
    }

    [Test]
    public void CanSeek_ReturnsFalse()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.That(timeoutStream.CanSeek, Is.False);
    }

    [Test]
    public void CanWrite_ReturnsFalse()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.That(timeoutStream.CanWrite, Is.False);
    }

    [Test]
    public void Length_ThrowsNotSupportedException()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.Throws<NotSupportedException>(() => _ = timeoutStream.Length);
    }

    [Test]
    public void Position_Get_ThrowsNotSupportedException()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.Throws<NotSupportedException>(() => _ = timeoutStream.Position);
    }

    [Test]
    public void Position_Set_ThrowsNotSupportedException()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.Throws<NotSupportedException>(() => timeoutStream.Position = 0);
    }

    [Test]
    public void Seek_ThrowsNotSupportedException()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.Throws<NotSupportedException>(() => timeoutStream.Seek(0, SeekOrigin.Begin));
    }

    [Test]
    public void SetLength_ThrowsNotSupportedException()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.Throws<NotSupportedException>(() => timeoutStream.SetLength(100));
    }

    [Test]
    public void Write_ThrowsNotSupportedException()
    {
        using var innerStream = new MemoryStream();
        using var timeoutStream = new TimeoutReadStream(innerStream);

        Assert.Throws<NotSupportedException>(() => timeoutStream.Write(new byte[1], 0, 1));
    }

    [Test]
    public void Constructor_WithNullStream_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new TimeoutReadStream(null!));
    }

    /// <summary>
    /// A stream that blocks indefinitely on read, useful for testing timeouts.
    /// </summary>
    private class BlockingStream : Stream
    {
        private readonly SemaphoreSlim _blockingSemaphore = new(0);
        private bool _disposed;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // Block until cancelled
            try
            {
                await _blockingSemaphore.WaitAsync(cancellationToken);
                return 0;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _blockingSemaphore.Dispose();
                }
                _disposed = true;
            }
            base.Dispose(disposing);
        }
    }
}
