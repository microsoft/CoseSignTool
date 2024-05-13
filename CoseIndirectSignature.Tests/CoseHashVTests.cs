// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose Deserialization

namespace CoseIndirectSignature.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography;
using CoseIndirectSignature.Exceptions;
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
    [TestCase(1, Description = "Default constructor.")]
    [TestCase(2, Description = "Sha256 with valid byte data.")]
    [TestCase(3, Description = "Sha256 with valid stream data.")]
    [TestCase(4, Description = "Sha256 with valid byte data, and a location.")]
    [TestCase(5, Description = "Sha256 with valid byte data, a location, and additionalData.")]
    [TestCase(6, Description = "Sha256 with valid stream, and a location.")]
    [TestCase(7, Description = "Sha256 with a valid stream, a location, and additionalData.")]
    [TestCase(8, Description = "Sha256 with a valid readonly memory.")]
    [TestCase(9, Description = "Sha256 with a valid readonly memory, and a location.")]
    [TestCase(10, Description = "Copy constructor.")]
    [TestCase(11, Description = "Bypass hash validation for explicit construction")]
    [TestCase(12, Description = "Bypass hash validation for explicit construction with a bogus algorithm, should serialize")]
    public void TestCoseHashVConstructorSuccess(int testCase)
    {
        // arrange
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        using MemoryStream stream = new(testData);
        ReadOnlyMemory<byte> rom = new(testData);
        CoseHashV testObj = new();
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
                testObj.AdditionalData = [0x03, 0x02, 0x01];
                CoseHashV other = new(testObj);
                other.Algorithm.Should().Be(testObj.Algorithm);
                other.HashValue.Should().BeEquivalentTo(testObj.HashValue);
                other.Location.Should().Be(testObj.Location);
                other.AdditionalData.Should().BeEquivalentTo(testObj.AdditionalData);
                break;
            case 11:
                CoseHashV testObject11 = new(CoseHashAlgorithm.SHA256, hashValue: [0x1, 0x2, 0x3], disableValidation: true);
                testObject11.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObject11.HashValue.Should().BeEquivalentTo(new byte[] { 0x1, 0x2, 0x3 });
                break;
            case 12:
                CoseHashV testObject12 = new((CoseHashAlgorithm)(-100), hashValue: [0x1, 0x2, 0x3], disableValidation: true);
                testObject12.Algorithm.Should().Be((CoseHashAlgorithm)(-100));
                testObject12.HashValue.Should().BeEquivalentTo(new byte[] { 0x1, 0x2, 0x3 });
                break;
            default:
                throw new InvalidDataException($"Test case {testCase} is not defined in {nameof(TestCoseHashVConstructorSuccess)}");
        }
    }

    [Test]
    [TestCase(1, Description = "Reserved algorithm case for byte ctor.")]
    [TestCase(2, Description = "Hash value that is not the size of the expected hash algorithm.")]
    [TestCase(3, Description = "Reserved algorithm case for stream ctor.")]
    [TestCase(4, Description = "Reserved algorithm case for byte ctor. and location")]
    [TestCase(5, Description = "Reserved algorithm case for byte ctor. and location and additionalData")]
    [TestCase(6, Description = "Reserved algorithm case for stream ctor. and location")]
    [TestCase(7, Description = "Reserved algorithm case for stream ctor. and location and additionalData")]
    [TestCase(8, Description = "SHA256Trunc64 algorithm for readonly memory byte array, and location")]
    [TestCase(9, Description = "SHAKE128 algorithm for readonly memory byte array and location and additionalData")]
    [TestCase(10, Description = "Null stream.")]
    [TestCase(11, Description = "Null byte data.")]
    [TestCase(12, Description = "Null read only data.")]
    [TestCase(13, Description = "Null hashValue")]
    [TestCase(14, Description = "0 length hashValue")]
    public void TestCoseHashVConstructorFailure(int testCase)
    {
        // arrange
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        using MemoryStream stream = new(testData);
        ReadOnlyMemory<byte> rom = new(testData);

        // act and assert
        Action act = () => new CoseHashV(CoseHashAlgorithm.Reserved, byteData: testData);
        switch (testCase)
        {
            case 1:
                act.Should().Throw<NotSupportedException>();
                break;
            case 2:
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, hashValue: testData);
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
            case 13:
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, hashValue: null);
                act.Should().Throw<ArgumentNullException>();
                break;
            case 14:
                act = () => new CoseHashV(CoseHashAlgorithm.SHA256, hashValue: []);
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
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        using MemoryStream stream = new(testData);
        ReadOnlyMemory<byte> rom = new(testData);
        CoseHashV testObj = new(CoseHashAlgorithm.SHA256, byteData: testData);

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
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        using MemoryStream stream = new(testData);
        ReadOnlyMemory<byte> rom = new(testData);
        CoseHashV testObj = new(CoseHashAlgorithm.SHA256, byteData: testData);

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
        CoseHashV testObj = new(CoseHashAlgorithm.SHA256, byteData: [0x01, 0x02, 0x03, 0x04]);

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
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        CoseHashV testObj = new(CoseHashAlgorithm.SHA256, byteData: testData);

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
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        CoseHashV testObj = new(CoseHashAlgorithm.SHA256, testData, location: "this is the location");

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
    [TestCase(1, Description = "Too few properties.")]
    [TestCase(2, Description = "Too many properties.")]
    [TestCase(3, Description = "Correct properties, but wrong type.")]
    [TestCase(4, Description = "Correct algorithm and hash, but wrong location type.")]
    [TestCase(5, Description = "Correct algorithm and hash, but wrong additionalData type.")]
    [TestCase(6, Description = "Correct algorithm, but hash length does not match algorithm.")]
    [TestCase(7, Description = "Not starting with start array")]
    [TestCase(8, Description = "Null Cbor reader")]
    [TestCase(9, Description = "Null byte array")]
    [TestCase(10, Description = "Invalid tstr encoding")]
    [TestCase(11, Description = "Valid tstr encoding")]
    [TestCase(12, Description ="Invalid algorithm integer - negative.")]
    [TestCase(13, Description = "Invalid algorithm integer - positive.")]
    [TestCase(14, Description = "Invalid algorithm integer, random hash, should deserialize with flag.")]
    [TestCase(15, Description = "Valid algorithm integer, random hash, should deserialize with flag.")]
    [TestCase(16, Description = "0 bytes to ReadOnlySpan<byte>")]
    [TestCase(17, Description = "Fuzz overflow")]
    [TestCase(18, Description = "Fuzz enum overflow")]
    public void TestObjectManualSerializationPaths(int testCase)
    {
        CborWriter? writer;
        int propertyCount = 1;
        byte[]? cborEcoding;
        switch (testCase)
        {
            // handle too few properties
            case 1:
                writer = new(CborConformanceMode.Strict);
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64((long)2);
                writer.WriteEndArray();

                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle too many properties
            case 2:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 5;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64((long)CoseHashAlgorithm.SHA256);
                writer.WriteByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 });
                writer.WriteTextString("location");
                writer.WriteByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 });
                writer.WriteBoolean(true);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle the correct amount, but the wrong types
            case 3:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteBoolean(true);
                writer.WriteBoolean(false);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle the correct algorithm and hash, but wrong type for location
            case 4:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 3;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64((long)CoseHashAlgorithm.SHA256);
                writer.WriteByteString(SHA256.HashData([0x01, 0x02, 0x03, 0x04]));
                writer.WriteBoolean(true);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle the correct algorithm, hash and location, but wrong type for additional data
            case 5:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 4;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64((long)CoseHashAlgorithm.SHA256);
                writer.WriteByteString(SHA256.HashData([0x01, 0x02, 0x03, 0x04]));
                writer.WriteTextString("location");
                writer.WriteBoolean(false);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle the correct algorithm but mismatched hash length.
            case 6:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64((long)CoseHashAlgorithm.SHA256);
                writer.WriteByteString([0x01, 0x02, 0x03, 0x04]);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle not starting with start array.
            case 7:
                writer = new(CborConformanceMode.Strict);
                writer.Reset();
                writer.WriteInt64((long)CoseHashAlgorithm.SHA256);
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle null reader
            case 8:
                Assert.ThrowsException<ArgumentNullException>(() => CoseHashV.Deserialize(reader: null));
                break;
            // handle null data
            case 9:
                Assert.ThrowsException<ArgumentNullException>(() => CoseHashV.Deserialize(data: null));
                break;
            // handle invalid tstr encoding of algorithm
            case 10:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteTextString("broken");
                writer.WriteByteString(SHA256.HashData([0x1, 0x2, 0x3, 0x4]));
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle a valid tstr encoding of algorithm
            case 11:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteTextString(CoseHashAlgorithm.SHA256.ToString());
                writer.WriteByteString(SHA256.HashData([0x1, 0x2, 0x3, 0x4]));
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                CoseHashV properDeserialization = CoseHashV.Deserialize(cborEcoding);
                properDeserialization.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                properDeserialization.HashValue.Should().BeEquivalentTo(SHA256.HashData([0x1, 0x2, 0x3, 0x4]));
                properDeserialization.Location.Should().BeNull();
                properDeserialization.AdditionalData.Should().BeNull();
                break;
            // handle an invalid algorithm integer negative.
            case 12:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64(-100);
                writer.WriteByteString(SHA256.HashData([0x1, 0x2, 0x3, 0x4]));
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle an invalid algorithm integer positive.
            case 13:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64(9999);
                writer.WriteByteString(SHA256.HashData([0x1, 0x2, 0x3, 0x4]));
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                Assert.ThrowsException<InvalidCoseDataException>(() => CoseHashV.Deserialize(cborEcoding));
                break;
            // handle an invalid algorithm integer positive, a random hash and pass the ignore validation flag.
            case 14:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64(-123);
                writer.WriteByteString([0x1, 0x2, 0x3, 0x4]);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                CoseHashV testObject14 = CoseHashV.Deserialize(cborEcoding, disableValidation: true);
                testObject14.Algorithm.Should().Be((CoseHashAlgorithm)(-123));
                testObject14.HashValue.Should().BeEquivalentTo([0x1, 0x2, 0x3, 0x4]);
                break;
            // handle an valid algorithm integer positive, a random hash and pass the ignore validation flag.
            case 15:
                writer = new(CborConformanceMode.Strict);
                propertyCount = 2;
                writer.Reset();
                writer.WriteStartArray(propertyCount);
                writer.WriteInt64((long)CoseHashAlgorithm.SHA256);
                writer.WriteByteString([0x1, 0x2, 0x3, 0x4]);
                writer.WriteEndArray();
                cborEcoding = writer.Encode();
                CoseHashV testObject15 = CoseHashV.Deserialize(cborEcoding, disableValidation: true);
                testObject15.Algorithm.Should().Be(CoseHashAlgorithm.SHA256);
                testObject15.HashValue.Should().BeEquivalentTo([0x1, 0x2, 0x3, 0x4]);
                break;
            // handle 0 bytes to ReadOnlySpan<byte>
            case 16:
                Action test16 = () => _ = CoseHashV.Deserialize((ReadOnlySpan<byte>)[]);
                test16.Should().Throw<InvalidCoseDataException>();
                break;
            // handle fuzz overflow
            case 17:
                byte[] fuzzData17 = Convert.FromBase64String("gjv//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////w==");
                Action test17 = () => _ = CoseHashV.Deserialize(fuzzData17);
                test17.Should().Throw<InvalidCoseDataException>();
                break;
            // handle fuzz enum overflow
            case 18:
                byte[] fuzzData18 = Convert.FromBase64String("hHc0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0Cg==");
                Action test18 = () => _ = CoseHashV.Deserialize(fuzzData18);
                test18.Should().Throw<InvalidCoseDataException>();
                break;

            default:
                throw new InvalidDataException($"Test case {testCase} is not defined in {nameof(TestObjectManualSerializationPaths)}");
        }
    }

    [Test]
    public void TestMismatchedHashAlgorithmAndHashSize()
    {
        // arrange
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        byte[] hash  = SHA512.HashData(testData);
        CoseHashV testObj = new(CoseHashAlgorithm.SHA256, byteData: hash);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => testObj.HashValue = hash);
    }

    [Test]
    [TestCase(1, Description = "Set invalid hash length through setter.")]
    [TestCase(2, Description = "Set null through setter.")]
    [TestCase(3, Description = "Set 0-length array through setter.")]
    public void TestSetHashWithoutAlgorithm(int testCase)
    {
        // arrange
        byte[] testData = [0x01, 0x02, 0x03, 0x04];
        byte[] hash = SHA256.HashData(testData);
        CoseHashV testObj = new();
        switch (testCase)
        {
            case 1:
                Assert.ThrowsException<ArgumentException>(() => testObj.HashValue = hash);
                break;
            case 2:
                Assert.ThrowsException<ArgumentNullException>(() => testObj.HashValue = null);
                break;
            case 3:
                Assert.ThrowsException<ArgumentOutOfRangeException>(() => testObj.HashValue = []);
                break;
            default:
                throw new InvalidDataException($"Test case {testCase} is not defined in {nameof(TestSetHashWithoutAlgorithm)}");
        }
    }
}
