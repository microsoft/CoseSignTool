// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature.Tests;

using System.Formats.Cbor;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NUnit.Framework.Internal;

/// <summary>
/// Class for Testing Methods of <see cref="CoseHashV"/>
/// </summary>
public class CoseHashVTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    [TestCase(4)]
    [TestCase(5)]
    [TestCase(6)]
    [TestCase(7)]
    [TestCase(8)]
    [TestCase(9)]
    [TestCase(10)]
    public void TestCoseHashVConstructorSuccess(int testCase)
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        using MemoryStream stream = new MemoryStream(testData);
        ReadOnlyMemory<byte> rom = new ReadOnlyMemory<byte>(testData);
        CoseHashV testObj = new CoseHashV();
        switch (testCase)
        {
            case 1:
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.Reserved);
                testObj.HashValue.Should().BeEmpty();
                testObj.Location.Should().BeNullOrWhiteSpace();
                testObj.AdditionalData.Should().BeNull();
                break;
            case 2:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, byteData: testData);
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().BeNullOrWhiteSpace();
                testObj.AdditionalData.Should().BeNull();
                break;
            case 3:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, stream);
                stream.Seek(0, SeekOrigin.Begin);
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().BeNullOrWhiteSpace();
                testObj.AdditionalData.Should().BeNull();
                break;
            case 4:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, testData, "location");
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().Be("location");
                testObj.AdditionalData.Should().BeNull();
                break;
            case 5:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, testData, "location", testData);
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().Be("location");
                testObj.AdditionalData.Should().BeEquivalentTo(testData);
                break;
            case 6:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, stream, "location");
                stream.Seek(0, SeekOrigin.Begin);
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().Be("location");
                testObj.AdditionalData.Should().BeNull();
                break;
            case 7:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, stream, "location", testData);
                stream.Seek(0, SeekOrigin.Begin);
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().Be("location");
                testObj.AdditionalData.Should().BeEquivalentTo(testData);
                break;
            case 8:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, rom, "location");
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().Be("location");
                testObj.AdditionalData.Should().BeNull();
                break;
            case 9:
                testObj = new CoseHashV(CoseHashAlgorithm.SHA256, rom, "location", rom);
                testObj.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObj.HashValue.Should().NotBeEmpty();
                testObj.HashValue.Length.Should().Be(32);
                testObj.Location.Should().Be("location");
                testObj.AdditionalData.Should().BeEquivalentTo(testData);
                break;
            case 10:
                CoseHashV other = new CoseHashV(testObj);
                other.Algorithm.Should().Be(testObj.Algorithm);
                other.HashValue.Should().BeEquivalentTo(testObj.HashValue);
                other.Location.Should().Be(testObj.Location);
                other.AdditionalData.Should().BeEquivalentTo(testObj.AdditionalData);
                break;
            default:
                throw new InvalidDataException($"Test case {testCase} is not defined in {nameof(TestCoseHashVConstructorSuccess)}");
        }
    }

    [Test]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    [TestCase(4)]
    [TestCase(5)]
    [TestCase(6)]
    [TestCase(7)]
    [TestCase(8)]
    [TestCase(9)]
    [TestCase(10)]
    [TestCase(11)]
    [TestCase(12)]
    public void TestCoseHashVConstructorFailure(int testCase)
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        using MemoryStream stream = new MemoryStream(testData);
        ReadOnlyMemory<byte> rom = new ReadOnlyMemory<byte>(testData);

        // act and assert
        Action act = () => new CoseHashV(CoseHashAlgorithm.Reserved, byteData: testData);
        switch (testCase)
        {
            case 1:
                act.Should().Throw<NotSupportedException>();
                break;
            case 2:
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, testData);
                act.Should().Throw<ArgumentException>();
                break;
            case 3:
                act = () => new CoseHashV(CoseHashAlgorithm.Reserved, stream);
                act.Should().Throw<NotSupportedException>();
                break;
            case 4:
                act = () => new CoseHashV(CoseHashAlgorithm.Reserved, testData, "location");
                act.Should().Throw<NotSupportedException>();
                break;
            case 5:
                act = () => new CoseHashV(CoseHashAlgorithm.SHAKE256, testData, "location", testData);
                act.Should().Throw<NotSupportedException>();
                break;
            case 6:
#pragma warning disable CS0618
                act = () => new CoseHashV(CoseHashAlgorithm.SHA1, stream, "location");
                act.Should().Throw<NotSupportedException>();
#pragma warning restore CS0618
                break;
            case 7:
#pragma warning disable CS0618
                act = () => new CoseHashV(CoseHashAlgorithm.SHA512Truc256, stream, "location", testData);
                act.Should().Throw<NotSupportedException>();
#pragma warning restore CS0618
                break;
            case 8:
#pragma warning disable CS0618
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256Trunc64, rom, "location");
                act.Should().Throw<NotSupportedException>();
#pragma warning restore CS0618
                break;
            case 9:
                act = () => new CoseHashV(CoseHashAlgorithm.SHAKE128, rom, "location", rom);
                act.Should().Throw<NotSupportedException>();
                break;
            case 10:
#nullable disable
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, streamData: null);
                act.Should().Throw<ArgumentNullException>();
#nullable restore
                break;
            case 11:
#nullable disable
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, byteData: null);
                act.Should().Throw<ArgumentNullException>();
#nullable restore
                break;
            case 12:
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, readonlyData: null);
                act.Should().Throw<ArgumentOutOfRangeException>();
                break;
            default:
                throw new InvalidDataException($"Test case {testCase} is not defined in {nameof(TestCoseHashVConstructorFailure)}");
        }
    }

    [Test]
    public void CoseHashVContentStreamMatchesTests()
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        using MemoryStream stream = new MemoryStream(testData);
        ReadOnlyMemory<byte> rom = new ReadOnlyMemory<byte>(testData);
        CoseHashV testObj = new CoseHashV(CoseHashAlgorithm.SHA256, byteData: testData);

        // act
        bool result = testObj.ContentMatches(testData);
        bool resultStream = testObj.ContentMatches(stream);
        bool resultRom = testObj.ContentMatches(rom);

        // assert
        result.Should().BeTrue();
        resultStream.Should().BeTrue();
        resultRom.Should().BeTrue();
    }

    [Test]
    public void CoseHashVContentStreamMatchesAsyncTests()
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        using MemoryStream stream = new MemoryStream(testData);
        ReadOnlyMemory<byte> rom = new ReadOnlyMemory<byte>(testData);
        CoseHashV testObj = new CoseHashV(CoseHashAlgorithm.SHA256, byteData: testData);

        // act
        bool result = testObj.ContentMatchesAsync(testData).Result;
        bool resultStream = testObj.ContentMatchesAsync(stream).Result;
        bool resultRom = testObj.ContentMatchesAsync(rom).Result;

        // assert
        result.Should().BeTrue();
        resultStream.Should().BeTrue();
        resultRom.Should().BeTrue();
    }

    [Test]
    public void ContentMatchesNullDataFailureTests()
    {
        // arrange
        CoseHashV testObj = new CoseHashV(CoseHashAlgorithm.SHA256, byteData: new byte[] { 0x01, 0x02, 0x03, 0x04 });

        // act and assert
#nullable disable
        Func<Task> act = async () => await testObj.ContentMatchesAsync(data: null).ConfigureAwait(false);
        act.Should().ThrowAsync<ArgumentNullException>();

        Action act2 = () => testObj.ContentMatches(stream: null);
        act2.Should().Throw<ArgumentNullException>();
#nullable restore
    }

    [Test]
    public void TestSerialization()
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        CoseHashV testObj = new CoseHashV(CoseHashAlgorithm.SHA256, byteData: testData);

        // act
        byte[] encoding = testObj.Serialize();
        CoseHashV newObj = CoseHashV.Deserialize(new CborReader(encoding));

        // assert
        encoding.Should().NotBeNull();
        encoding.Length.Should().BeGreaterThan(0);
        newObj.Algorithm.Should().Be(testObj.Algorithm);
        newObj.HashValue.Should().BeEquivalentTo(testObj.HashValue);
        newObj.Location.Should().Be(testObj.Location);
        newObj.AdditionalData.Should().BeEquivalentTo(testObj.AdditionalData);
    }

    [Test]
    public void TestSerializationWithOptionalFields()
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        CoseHashV testObj = new CoseHashV(CoseHashAlgorithm.SHA256, testData, location: "this is the location");

        // act
        byte[] encoding = testObj.Serialize();
        CoseHashV newObj = CoseHashV.Deserialize(encoding);

        // assert
        encoding.Should().NotBeNull();
        encoding.Length.Should().BeGreaterThan(0);
        newObj.Algorithm.Should().Be(testObj.Algorithm);
        newObj.HashValue.Should().BeEquivalentTo(testObj.HashValue);
        newObj.Location.Should().Be(testObj.Location);
        newObj.AdditionalData.Should().BeEquivalentTo(testObj.AdditionalData);

        testObj = new CoseHashV(CoseHashAlgorithm.SHA256, testData, location: "this is the location", additionalData: [0x01, 0x03, 0x04]);

        // act
        encoding = testObj.Serialize();
        newObj = CoseHashV.Deserialize(encoding);

        // assert
        encoding.Should().NotBeNull();
        encoding.Length.Should().BeGreaterThan(0);
        newObj.Algorithm.Should().Be(testObj.Algorithm);
        newObj.HashValue.Should().BeEquivalentTo(testObj.HashValue);
        newObj.Location.Should().Be(testObj.Location);
        newObj.AdditionalData.Should().BeEquivalentTo(testObj.AdditionalData);
    }

    [Test]
    public void TestMismatchedHashAlgorithmAndHashSize()
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        using SHA512 sha = SHA512.Create();

        byte[] hash  = sha.ComputeHash(testData);
        CoseHashV testObj = new CoseHashV(CoseHashAlgorithm.SHA256, byteData: hash);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => testObj.HashValue = hash);
    }

    [Test]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    public void TestSetHashWithoutAlgorithm(int testCase)
    {
        // arrange
        byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        using SHA256 sha = SHA256.Create();

        byte[] hash = sha.ComputeHash(testData);
        CoseHashV testObj = new CoseHashV();
        switch (testCase)
        {
            case 1:
                Assert.ThrowsException<ArgumentException>(() => testObj.HashValue = hash);
                break;
            case 2:
                Assert.ThrowsException<ArgumentNullException>(() => testObj.HashValue = null);
                break;
            case 3:
                Assert.ThrowsException<ArgumentOutOfRangeException>(() => testObj.HashValue = new byte[0]);
                break;
            default:
                throw new InvalidDataException($"Test case {testCase} is not defined in {nameof(TestSetHashWithoutAlgorithm)}");
        }
    }
}
