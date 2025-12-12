// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Formats.Cbor;
using CoseSign1.Transparent.MST.Extensions;

/// <summary>
/// Unit tests for the <see cref="BinaryDataExtensions"/> class.
/// </summary>
[TestFixture]
[Parallelizable(ParallelScope.All)]
public class BinaryDataExtensionsTests
{
    /// <summary>
    /// Tests the <see cref="BinaryDataExtensions.TryGetMstEntryId"/> method for null input.
    /// </summary>
    [Test]
    public void TryGetMstEntryId_ReturnsFalse_WhenBinaryDataIsNull()
    {
        // Arrange
        BinaryData binaryData = null;

        // Act
        bool result = binaryData.TryGetMstEntryId(out string? entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.EqualTo(string.Empty));
    }

    /// <summary>
    /// Tests the <see cref="BinaryDataExtensions.TryGetMstEntryId"/> method for valid CBOR data containing "EntryId".
    /// </summary>
    [Test]
    public void TryGetMstEntryId_ReturnsTrue_WhenEntryIdIsPresent()
    {
        // Arrange
        string expectedEntryId = "12345";
        BinaryData binaryData = CreateCborBinaryDataWithEntryId(expectedEntryId);

        // Act
        bool result = binaryData.TryGetMstEntryId(out string? entryId);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(entryId, Is.EqualTo(expectedEntryId));
    }

    /// <summary>
    /// Tests the <see cref="BinaryDataExtensions.TryGetMstEntryId"/> method for valid CBOR data without "EntryId".
    /// </summary>
    [Test]
    public void TryGetMstEntryId_ReturnsFalse_WhenEntryIdIsNotPresent()
    {
        // Arrange
        BinaryData binaryData = CreateCborBinaryDataWithoutEntryId();

        // Act
        bool result = binaryData.TryGetMstEntryId(out string? entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.EqualTo(string.Empty));
    }

    /// <summary>
    /// Tests the <see cref="BinaryDataExtensions.TryGetMstEntryId"/> method for invalid CBOR data.
    /// </summary>
    [Test]
    public void TryGetMstEntryId_ReturnsFalse_WhenCborDataIsInvalid()
    {
        // Arrange
        BinaryData binaryData = BinaryData.FromBytes(new byte[] { 0xFF, 0xFF, 0xFF });

        // Act
        bool result = binaryData.TryGetMstEntryId(out string? entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.EqualTo(string.Empty));
    }

    /// <summary>
    /// Tests the <see cref="BinaryDataExtensions.TryGetMstEntryId"/> method for CBOR data with unexpected structure.
    /// </summary>
    [Test]
    public void TryGetMstEntryId_ReturnsFalse_WhenCborDataHasUnexpectedStructure()
    {
        // Arrange
        BinaryData binaryData = CreateCborBinaryDataWithUnexpectedStructure();

        // Act
        bool result = binaryData.TryGetMstEntryId(out string? entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.EqualTo(string.Empty));
    }

    /// <summary>
    /// Helper method to create a <see cref="BinaryData"/> object with valid CBOR data containing "EntryId".
    /// </summary>
    /// <param name="entryId">The "EntryId" value to include in the CBOR data.</param>
    /// <returns>A <see cref="BinaryData"/> object containing the CBOR-encoded data.</returns>
    private static BinaryData CreateCborBinaryDataWithEntryId(string entryId)
    {
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartMap(1);
        cborWriter.WriteTextString("EntryId");
        cborWriter.WriteTextString(entryId);
        cborWriter.WriteEndMap();
        return BinaryData.FromBytes(cborWriter.Encode());
    }

    /// <summary>
    /// Helper method to create a <see cref="BinaryData"/> object with valid CBOR data without "EntryId".
    /// </summary>
    /// <returns>A <see cref="BinaryData"/> object containing the CBOR-encoded data.</returns>
    private static BinaryData CreateCborBinaryDataWithoutEntryId()
    {
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartMap(1);
        cborWriter.WriteTextString("OtherKey");
        cborWriter.WriteTextString("OtherValue");
        cborWriter.WriteEndMap();
        return BinaryData.FromBytes(cborWriter.Encode());
    }

    /// <summary>
    /// Helper method to create a <see cref="BinaryData"/> object with CBOR data having an unexpected structure.
    /// </summary>
    /// <returns>A <see cref="BinaryData"/> object containing the CBOR-encoded data.</returns>
    private static BinaryData CreateCborBinaryDataWithUnexpectedStructure()
    {
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartArray(2);
        cborWriter.WriteTextString("EntryId");
        cborWriter.WriteTextString("12345");
        cborWriter.WriteEndArray();
        return BinaryData.FromBytes(cborWriter.Encode());
    }
}

