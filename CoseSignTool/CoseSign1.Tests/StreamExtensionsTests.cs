// ---------------------------------------------------------------------------
// <copyright file="StreamExtensionsTests.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Tests;

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
}
