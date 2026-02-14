// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

using System;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class StreamExtensionsTests
{
    [Test]
    public void IsNullOrEmpty_NullStream()
    {
        MemoryStream? stream = null;
        stream.IsNullOrEmpty().Should().Be(true);
    }

    [Test]
    public void IsNullOrEmpty_EmptyStream()
    {
        // Create a 0-byte file and read it as a stream
        string filePath = Path.GetTempFileName();
        Stream stream = new FileInfo(filePath).OpenRead();
        stream.IsNullOrEmpty().Should().Be(true);
    }

    [Test]
    public void IsNullOrEmpty_NonEmptyStream()
    {
        // Create a file with content and read it as a stream
        string filePath = Path.GetTempFileName();
        File.WriteAllText(filePath, "abc");
        Stream stream = new FileInfo(filePath).OpenRead();
        stream.IsNullOrEmpty().Should().Be(false);
    }

    [Test]
    public void IsNullOrEmpty_NonSeekableStream()
    {
        // Create a stream with content that cannot seek and ensure that is returns IsNullOrEmpty = false
        using MemoryStream memory = new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        Mock<Stream> mockStream = new(MockBehavior.Strict);
        mockStream.Setup(s => s.CanSeek).Returns(false);
        mockStream.Setup(s => s.Position).Returns(memory.Position);
        mockStream.Setup(s => s.Length).Returns(memory.Length);
        mockStream.Setup(s => s.Read(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>())).Returns((byte[] buffer, int offset, int count) => memory.Read(buffer, offset, count));
        mockStream.Setup(s => s.ReadAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>())).Returns((byte[] buffer, int offset, int count, CancellationToken ct) => memory.ReadAsync(buffer, offset, count, ct));

        mockStream.Object.IsNullOrEmpty().Should().Be(false);
    }

    [Test]
    public void IsNullOrEmpty_NonSeekableStreamNoLength()
    {
        // Create a stream without content that cannot seek and ensure that is returns IsNullOrEmpty = true
        using MemoryStream memory = new();
        Mock<Stream> mockStream = new(MockBehavior.Strict);
        mockStream.Setup(s => s.CanSeek).Returns(false);
        mockStream.Setup(s => s.Position).Returns(memory.Position);
        mockStream.Setup(s => s.Length).Returns(memory.Length);
        mockStream.Setup(s => s.Read(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>())).Returns((byte[] buffer, int offset, int count) => memory.Read(buffer, offset, count));
        mockStream.Setup(s => s.ReadAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>())).Returns((byte[] buffer, int offset, int count, CancellationToken ct) => memory.ReadAsync(buffer, offset, count, ct));

        mockStream.Object.IsNullOrEmpty().Should().Be(true);
    }

    [Test]
    public void IsNullOrEmpty_NonSeekablePipedStream_ShouldReturnFalse()
    {
        // Simulate piped stdin on Linux/macOS where Length throws NotSupportedException
        // This should return false (not empty) since we assume readable streams have content
        Mock<Stream> mockStream = new(MockBehavior.Strict);
        mockStream.Setup(s => s.CanSeek).Returns(false);
        mockStream.Setup(s => s.CanRead).Returns(true);
        mockStream.Setup(s => s.Length).Throws(new NotSupportedException("Stream does not support seeking."));

        mockStream.Object.IsNullOrEmpty().Should().Be(false);
    }

    [Test]
    public void IsNullOrEmpty_WithTimeout()
    {        
        byte[] buffer = Encoding.ASCII.GetBytes("Hello test");
        using DelayedMemoryStream memory = new(buffer, 1000);

        // Try with default max wait of 100ms
        memory.IsNullOrEmpty().Should().Be(true);

        // Try with a 2 second max delay
        memory.IsNullOrEmpty(2000).Should().Be(false);
    }

    public class DelayedMemoryStream : MemoryStream
    {
        private readonly int Delay;

        public DelayedMemoryStream(byte[] content, int delay)
        {
            Write(content, 0, content.Length);
            Position = 0;
            Delay = delay;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // Introduce a delay before reading
            await Task.Delay(Delay, cancellationToken);

            // Call the base class's ReadAsync method
            return await base.ReadAsync(buffer, offset, count, cancellationToken);
        }
    }
}
