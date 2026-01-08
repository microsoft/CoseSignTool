// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using CoseSign1.Transparent.MST.Extensions;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class BinaryDataExtensionsTests
{
    #region TryGetMstEntryId Tests

    [Test]
    public void TryGetMstEntryId_WithNullBinaryData_ReturnsFalse()
    {
        // Arrange
        BinaryData? binaryData = null;

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithValidEntryId_ReturnsTrue()
    {
        // Arrange
        var binaryData = CreateCborMapWithEntryId("1.234");

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(entryId, Is.EqualTo("1.234"));
    }

    [Test]
    public void TryGetMstEntryId_WithEmptyEntryId_ReturnsTrue()
    {
        // Arrange
        var binaryData = CreateCborMapWithEntryId("");

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(entryId, Is.EqualTo(""));
    }

    [Test]
    public void TryGetMstEntryId_WithMultipleKeys_FindsEntryId()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("OperationId");
        writer.WriteTextString("op-123");
        writer.WriteTextString("EntryId");
        writer.WriteTextString("5.678");
        writer.WriteTextString("Status");
        writer.WriteTextString("Succeeded");
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(entryId, Is.EqualTo("5.678"));
    }

    [Test]
    public void TryGetMstEntryId_WithoutEntryIdKey_ReturnsFalse()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteTextString("OperationId");
        writer.WriteTextString("op-123");
        writer.WriteTextString("Status");
        writer.WriteTextString("Succeeded");
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithInvalidCbor_ReturnsFalse()
    {
        // Arrange - invalid CBOR bytes
        var binaryData = BinaryData.FromBytes(new byte[] { 0xFF, 0xFE, 0xFD });

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithNonMapCbor_ReturnsFalse()
    {
        // Arrange - CBOR array instead of map
        var writer = new CborWriter();
        writer.WriteStartArray(2);
        writer.WriteTextString("item1");
        writer.WriteTextString("item2");
        writer.WriteEndArray();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithEmptyMap_ReturnsFalse()
    {
        // Arrange - empty CBOR map
        var writer = new CborWriter();
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithNonTextValueType_ReturnsFalse()
    {
        // Arrange - EntryId key but integer value instead of text
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteTextString("EntryId");
        writer.WriteInt32(12345);  // Integer instead of text
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert - FormatException caught
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithCaseSensitiveKey_OnlyMatchesExact()
    {
        // Arrange - different case for key
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteTextString("entryid");  // lowercase
        writer.WriteTextString("1.234");
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert - case sensitive, so should not match
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithEmptyBinaryData_ReturnsFalse()
    {
        // Arrange
        var binaryData = BinaryData.FromBytes(Array.Empty<byte>());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(entryId, Is.Null);
    }

    [Test]
    public void TryGetMstEntryId_WithEntryIdAsFirstKey_ReturnsEarly()
    {
        // Arrange - EntryId as first key for early return
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("EntryId");
        writer.WriteTextString("first.entry");
        writer.WriteTextString("Other");
        writer.WriteTextString("value");
        writer.WriteTextString("Another");
        writer.WriteTextString("data");
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(entryId, Is.EqualTo("first.entry"));
    }

    [Test]
    public void TryGetMstEntryId_WithNestedMap_SkipsNestedValue()
    {
        // Arrange - nested map value that should be skipped
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteTextString("Nested");
        writer.WriteStartMap(1);
        writer.WriteTextString("Inner");
        writer.WriteTextString("Value");
        writer.WriteEndMap();
        writer.WriteTextString("EntryId");
        writer.WriteTextString("after.nested");
        writer.WriteEndMap();
        var binaryData = BinaryData.FromBytes(writer.Encode());

        // Act
        var result = binaryData.TryGetMstEntryId(out var entryId);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(entryId, Is.EqualTo("after.nested"));
    }

    #endregion

    #region Helper Methods

    private static BinaryData CreateCborMapWithEntryId(string entryId)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(1);
        writer.WriteTextString("EntryId");
        writer.WriteTextString(entryId);
        writer.WriteEndMap();
        return BinaryData.FromBytes(writer.Encode());
    }

    #endregion
}
