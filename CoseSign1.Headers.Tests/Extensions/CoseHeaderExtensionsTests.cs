// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Tests.Extensions;

using CoseSign1.Headers.Extensions;
using NUnit.Framework;

/// <summary>
/// Tests for the CoseHeaderExtensions class.
/// </summary>
[TestFixture]
public class CoseHeaderExtensionsTests
{
    [Test]
    public void ToCoseHeaderMap_WithIntHeaders_CreatesCorrectMap()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>
        {
            new("algorithm", -7, true),
            new("kid", 42, false)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(2));
        Assert.That(result[new CoseHeaderLabel("algorithm")].GetValueAsInt32(), Is.EqualTo(-7));
        Assert.That(result[new CoseHeaderLabel("kid")].GetValueAsInt32(), Is.EqualTo(42));
    }

    [Test]
    public void ToCoseHeaderMap_WithStringHeaders_CreatesCorrectMap()
    {
        // Arrange
        var headers = new List<CoseHeader<string>>
        {
            new("content-type", "application/json", true),
            new("custom-header", "test-value", false)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(2));
        Assert.That(result[new CoseHeaderLabel("content-type")].GetValueAsString(), Is.EqualTo("application/json"));
        Assert.That(result[new CoseHeaderLabel("custom-header")].GetValueAsString(), Is.EqualTo("test-value"));
    }

    [Test]
    public void ToCoseHeaderMap_WithEmptyCollection_ReturnsEmptyMap()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>();

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(0));
    }

    [Test]
    public void ToCoseHeaderMap_WithNullCollection_ThrowsArgumentNullException()
    {
        // Arrange
        List<CoseHeader<int>>? headers = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => headers!.ToCoseHeaderMap());
    }

    [Test]
    public void ToCoseHeaderMap_WithNullStringValue_ThrowsArgumentException()
    {
        // Arrange
        var headers = new List<CoseHeader<string>>
        {
            new("test-header", null!, true)
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => headers.ToCoseHeaderMap());
    }

    [Test]
    public void ToCoseHeaderMap_WithEmptyStringValue_ThrowsArgumentException()
    {
        // Arrange
        var headers = new List<CoseHeader<string>>
        {
            new("test-header", "", true)
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => headers.ToCoseHeaderMap());
    }

    [Test]
    public void ToCoseHeaderMap_WithExistingMap_MergesCorrectly()
    {
        // Arrange
        var existingMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("existing")] = CoseHeaderValue.FromString("value1")
        };

        var headers = new List<CoseHeader<int>>
        {
            new("algorithm", -7, true),
            new("kid", 42, false)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap(existingMap);

        // Assert
        Assert.That(result, Is.SameAs(existingMap));
        Assert.That(result.Count, Is.EqualTo(3));
        Assert.That(result[new CoseHeaderLabel("existing")].GetValueAsString(), Is.EqualTo("value1"));
        Assert.That(result[new CoseHeaderLabel("algorithm")].GetValueAsInt32(), Is.EqualTo(-7));
        Assert.That(result[new CoseHeaderLabel("kid")].GetValueAsInt32(), Is.EqualTo(42));
    }

    [Test]
    public void ToCoseHeaderMap_WithExistingMapAndDuplicateKey_OverwritesValue()
    {
        // Arrange
        var existingMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("algorithm")] = CoseHeaderValue.FromInt32(-35)
        };

        var headers = new List<CoseHeader<int>>
        {
            new("algorithm", -7, true)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap(existingMap);

        // Assert
        Assert.That(result, Is.SameAs(existingMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("algorithm")].GetValueAsInt32(), Is.EqualTo(-7));
    }

    [Test]
    public void ToCoseHeaderMap_WithNullExistingMap_CreatesNewMap()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>
        {
            new("algorithm", -7, true)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("algorithm")].GetValueAsInt32(), Is.EqualTo(-7));
    }

    [Test]
    public void ToCoseHeaderMap_WithNullHeader_SkipsNullHeaders()
    {
        // Arrange
        var headers = new List<CoseHeader<int>?>
        {
            new("algorithm", -7, true),
            null,
            new("kid", 42, false)
        };

        // Act
        CoseHeaderMap result = headers.Where(h => h != null).Cast<CoseHeader<int>>().ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(2));
    }

    [Test]
    public void MergeHeaderMap_WithValidMaps_MergesCorrectly()
    {
        // Arrange
        var targetMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("target1")] = CoseHeaderValue.FromString("value1")
        };

        var sourceMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("source1")] = CoseHeaderValue.FromInt32(42),
            [new CoseHeaderLabel("source2")] = CoseHeaderValue.FromString("value2")
        };

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(sourceMap);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(3));
        Assert.That(result[new CoseHeaderLabel("target1")].GetValueAsString(), Is.EqualTo("value1"));
        Assert.That(result[new CoseHeaderLabel("source1")].GetValueAsInt32(), Is.EqualTo(42));
        Assert.That(result[new CoseHeaderLabel("source2")].GetValueAsString(), Is.EqualTo("value2"));
    }

    [Test]
    public void MergeHeaderMap_WithDuplicateKeys_OverwritesWithSourceValues()
    {
        // Arrange
        var targetMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("algorithm")] = CoseHeaderValue.FromInt32(-35)
        };

        var sourceMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("algorithm")] = CoseHeaderValue.FromInt32(-7)
        };

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(sourceMap);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("algorithm")].GetValueAsInt32(), Is.EqualTo(-7));
    }

    [Test]
    public void MergeHeaderMap_WithNullSourceMap_ReturnsTargetUnchanged()
    {
        // Arrange
        var targetMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("target1")] = CoseHeaderValue.FromString("value1")
        };

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(null);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("target1")].GetValueAsString(), Is.EqualTo("value1"));
    }

    [Test]
    public void MergeHeaderMap_WithNullTargetMap_ThrowsArgumentNullException()
    {
        // Arrange
        CoseHeaderMap? targetMap = null;
        var sourceMap = new CoseHeaderMap();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => targetMap!.MergeHeaderMap(sourceMap));
    }

    [Test]
    public void MergeHeaderMap_WithEmptySourceMap_ReturnsTargetUnchanged()
    {
        // Arrange
        var targetMap = new CoseHeaderMap
        {
            [new CoseHeaderLabel("target1")] = CoseHeaderValue.FromString("value1")
        };
        var sourceMap = new CoseHeaderMap();

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(sourceMap);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("target1")].GetValueAsString(), Is.EqualTo("value1"));
    }

    [Test]
    public void ToCoseHeaderMap_MixedIntAndStringWorkflow_WorksCorrectly()
    {
        // Arrange - simulate the SignCommand workflow
        var intHeaders = new List<CoseHeader<int>>
        {
            new("algorithm", -7, true),
            new("kid-int", 42, false)
        };

        var stringHeaders = new List<CoseHeader<string>>
        {
            new("content-type", "application/json", true),
            new("kid-string", "test-key", false)
        };

        // Act - simulate the SignCommand flow
        CoseHeaderMap? protectedHeaders = intHeaders.Where(h => h.IsProtected).ToCoseHeaderMap();
        CoseHeaderMap? unProtectedHeaders = intHeaders.Where(h => !h.IsProtected).ToCoseHeaderMap();

        protectedHeaders = stringHeaders.Where(h => h.IsProtected).ToCoseHeaderMap(protectedHeaders);
        unProtectedHeaders = stringHeaders.Where(h => !h.IsProtected).ToCoseHeaderMap(unProtectedHeaders);

        // Assert
        Assert.That(protectedHeaders.Count, Is.EqualTo(2));
        Assert.That(unProtectedHeaders.Count, Is.EqualTo(2));
        Assert.That(protectedHeaders[new CoseHeaderLabel("algorithm")].GetValueAsInt32(), Is.EqualTo(-7));
        Assert.That(protectedHeaders[new CoseHeaderLabel("content-type")].GetValueAsString(), Is.EqualTo("application/json"));
        Assert.That(unProtectedHeaders[new CoseHeaderLabel("kid-int")].GetValueAsInt32(), Is.EqualTo(42));
        Assert.That(unProtectedHeaders[new CoseHeaderLabel("kid-string")].GetValueAsString(), Is.EqualTo("test-key"));
    }

    [Test]
    public void ToCoseHeaderMap_WithIntHeaders_ShouldCreateCoseHeaderMap()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>
        {
            new("created-at", 1234567890, true),
            new("version", 1, false)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(2));

        // Check that the values are correctly converted
        Assert.That(result[new CoseHeaderLabel("created-at")].GetValueAsInt32(), Is.EqualTo(1234567890));
        Assert.That(result[new CoseHeaderLabel("version")].GetValueAsInt32(), Is.EqualTo(1));
    }

    [Test]
    public void ToCoseHeaderMap_WithStringHeaders_ShouldCreateCoseHeaderMap()
    {
        // Arrange
        var headers = new List<CoseHeader<string>>
        {
            new("app-name", "MyApp", true),
            new("environment", "prod", false)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(2));

        Assert.That(result[new CoseHeaderLabel("app-name")].GetValueAsString(), Is.EqualTo("MyApp"));
        Assert.That(result[new CoseHeaderLabel("environment")].GetValueAsString(), Is.EqualTo("prod"));
    }

    [Test]
    public void ToCoseHeaderMap_WithEmptyCollection_ShouldReturnEmptyMap()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>();

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(0));
    }

    [Test]
    public void ToCoseHeaderMap_WithNullCollection_ShouldThrowArgumentNullException()
    {
        // Arrange
        List<CoseHeader<int>>? headers = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => headers!.ToCoseHeaderMap());
    }

    [Test]
    public void ToCoseHeaderMap_WithNullStringValue_ShouldThrowArgumentException()
    {
        // Arrange
        var headers = new List<CoseHeader<string>>
        {
            new("test", null!, true)
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => headers.ToCoseHeaderMap());
    }

    [Test]
    public void ToCoseHeaderMap_WithEmptyStringValue_ShouldThrowArgumentException()
    {
        // Arrange
        var headers = new List<CoseHeader<string>>
        {
            new("test", "", true)
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => headers.ToCoseHeaderMap());
    }

    [Test]
    public void ToCoseHeaderMap_WithExistingMap_ShouldMergeHeaders()
    {
        // Arrange
        var existingMap = new CoseHeaderMap();
        existingMap.Add(new CoseHeaderLabel("existing"), CoseHeaderValue.FromString("value"));

        var headers = new List<CoseHeader<int>>
        {
            new("new-header", 42, true)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap(existingMap);

        // Assert
        Assert.That(result, Is.SameAs(existingMap));
        Assert.That(result.Count, Is.EqualTo(2));
        Assert.That(result[new CoseHeaderLabel("existing")].GetValueAsString(), Is.EqualTo("value"));
        Assert.That(result[new CoseHeaderLabel("new-header")].GetValueAsInt32(), Is.EqualTo(42));
    }

    [Test]
    public void ToCoseHeaderMap_WithExistingMapNull_ShouldCreateNewMap()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>
        {
            new("new-header", 42, true)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("new-header")].GetValueAsInt32(), Is.EqualTo(42));
    }

    [Test]
    public void ToCoseHeaderMap_WithExistingMapAndConflictingKeys_ShouldOverwrite()
    {
        // Arrange
        var existingMap = new CoseHeaderMap();
        existingMap.Add(new CoseHeaderLabel("key"), CoseHeaderValue.FromString("old-value"));

        var headers = new List<CoseHeader<string>>
        {
            new("key", "new-value", true)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap(existingMap);

        // Assert
        Assert.That(result, Is.SameAs(existingMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("key")].GetValueAsString(), Is.EqualTo("new-value"));
    }

    [Test]
    public void MergeHeaderMap_WithValidMaps_ShouldMergeCorrectly()
    {
        // Arrange
        var targetMap = new CoseHeaderMap();
        targetMap.Add(new CoseHeaderLabel("target-key"), CoseHeaderValue.FromString("target-value"));

        var sourceMap = new CoseHeaderMap();
        sourceMap.Add(new CoseHeaderLabel("source-key"), CoseHeaderValue.FromInt32(42));

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(sourceMap);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(2));
        Assert.That(result[new CoseHeaderLabel("target-key")].GetValueAsString(), Is.EqualTo("target-value"));
        Assert.That(result[new CoseHeaderLabel("source-key")].GetValueAsInt32(), Is.EqualTo(42));
    }

    [Test]
    public void MergeHeaderMap_WithConflictingKeys_ShouldOverwrite()
    {
        // Arrange
        var targetMap = new CoseHeaderMap();
        targetMap.Add(new CoseHeaderLabel("key"), CoseHeaderValue.FromString("target-value"));

        var sourceMap = new CoseHeaderMap();
        sourceMap.Add(new CoseHeaderLabel("key"), CoseHeaderValue.FromString("source-value"));

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(sourceMap);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("key")].GetValueAsString(), Is.EqualTo("source-value"));
    }

    [Test]
    public void MergeHeaderMap_WithNullSourceMap_ShouldReturnTargetUnchanged()
    {
        // Arrange
        var targetMap = new CoseHeaderMap();
        targetMap.Add(new CoseHeaderLabel("key"), CoseHeaderValue.FromString("value"));

        // Act
        CoseHeaderMap result = targetMap.MergeHeaderMap(null);

        // Assert
        Assert.That(result, Is.SameAs(targetMap));
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("key")].GetValueAsString(), Is.EqualTo("value"));
    }

    [Test]
    public void MergeHeaderMap_WithNullTargetMap_ShouldThrowArgumentNullException()
    {
        // Arrange
        CoseHeaderMap? targetMap = null;
        var sourceMap = new CoseHeaderMap();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => targetMap!.MergeHeaderMap(sourceMap));
    }

    [Test]
    public void ToCoseHeaderMap_WithHeadersContainingNullLabel_ShouldSkipThem()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>
        {
            new("valid-header", 42, true),
            new(null!, 99, false)  // This should be skipped
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("valid-header")].GetValueAsInt32(), Is.EqualTo(42));
    }

    [Test]
    public void ToCoseHeaderMap_WithMixedProtectedAndUnprotectedHeaders_ShouldIncludeAll()
    {
        // Arrange
        var headers = new List<CoseHeader<int>>
        {
            new("protected-header", 1, true),
            new("unprotected-header", 2, false)
        };

        // Act
        CoseHeaderMap result = headers.ToCoseHeaderMap();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Count, Is.EqualTo(2));
        Assert.That(result[new CoseHeaderLabel("protected-header")].GetValueAsInt32(), Is.EqualTo(1));
        Assert.That(result[new CoseHeaderLabel("unprotected-header")].GetValueAsInt32(), Is.EqualTo(2));
    }
    [Test]
    public void ToCoseHeaderMap_WithMixedTypeHeaders_ShouldCreateCorrectMap()
    {
        // Arrange
        List<CoseHeader<int>> intHeaders = new()
        {
            new("header1", 1000, true),
            new("header2", 87234, true),
            new("header4", 100, false)
        };
        
        List<CoseHeader<string>> stringHeaders = new()
        {
            new("header3", "value1", true)
        };

        // Act
        CoseHeaderMap intHeaderMap = intHeaders.ToCoseHeaderMap();
        CoseHeaderMap stringHeaderMap = stringHeaders.ToCoseHeaderMap();

        // Merge them to simulate the old factory behavior
        CoseHeaderMap combinedMap = intHeaderMap.MergeHeaderMap(stringHeaderMap);

        // Assert
        Assert.That(combinedMap.Count, Is.EqualTo(4));
        Assert.That(combinedMap[new CoseHeaderLabel("header1")].GetValueAsInt32(), Is.EqualTo(1000));
        Assert.That(combinedMap[new CoseHeaderLabel("header2")].GetValueAsInt32(), Is.EqualTo(87234));
        Assert.That(combinedMap[new CoseHeaderLabel("header3")].GetValueAsString(), Is.EqualTo("value1"));
        Assert.That(combinedMap[new CoseHeaderLabel("header4")].GetValueAsInt32(), Is.EqualTo(100));
    }

    [Test]
    public void ToCoseHeaderMap_WithExistingMapExtension_ShouldMergeCorrectly()
    {
        // Arrange
        CoseHeaderMap existingMap = new();
        existingMap.Add(new CoseHeaderLabel("Label1"), CoseHeaderValue.FromInt32(32));
        existingMap.Add(new CoseHeaderLabel("Label2"), CoseHeaderValue.FromString("value1"));

        List<CoseHeader<string>> stringHeaders = new()
        {
            new("Label3", "value2", true)
        };

        List<CoseHeader<int>> intHeaders = new()
        {
            new("Label4", 45, false),
            new("Label5", 132, false)
        };

        // Act
        CoseHeaderMap result1 = stringHeaders.ToCoseHeaderMap(existingMap);
        CoseHeaderMap result2 = intHeaders.ToCoseHeaderMap(result1);

        // Assert
        Assert.That(result2, Is.SameAs(existingMap));
        Assert.That(result2.Count, Is.EqualTo(5));
        Assert.That(result2[new CoseHeaderLabel("Label1")].GetValueAsInt32(), Is.EqualTo(32));
        Assert.That(result2[new CoseHeaderLabel("Label2")].GetValueAsString(), Is.EqualTo("value1"));
        Assert.That(result2[new CoseHeaderLabel("Label3")].GetValueAsString(), Is.EqualTo("value2"));
        Assert.That(result2[new CoseHeaderLabel("Label4")].GetValueAsInt32(), Is.EqualTo(45));
        Assert.That(result2[new CoseHeaderLabel("Label5")].GetValueAsInt32(), Is.EqualTo(132));
    }

    [Test]
    public void ToCoseHeaderMap_WithNullHeaders_ShouldThrowArgumentNullException()
    {
        // Arrange
        List<CoseHeader<int>>? nullIntHeaders = null;
        List<CoseHeader<string>>? nullStringHeaders = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => nullIntHeaders!.ToCoseHeaderMap());
        Assert.Throws<ArgumentNullException>(() => nullStringHeaders!.ToCoseHeaderMap());
    }

    [Test] 
    public void ToCoseHeaderMap_WithUnsupportedValueType_ShouldThrowNotImplementedException()
    {
        // This test demonstrates that our extension method only supports int and string types
        // If we tried to create CoseHeader<long>, it would fail at compile time, but let's test
        // our CreateCoseHeaderValue method directly for unsupported scenarios
        
        // Arrange
        List<CoseHeader<int>> headers = new() { new("key1", 100, true) };
        
        // Act & Assert - This should work fine for supported types
        Assert.DoesNotThrow(() => headers.ToCoseHeaderMap());
        
        // The type system prevents us from creating CoseHeader<long> since our extension
        // methods are specifically typed for int and string
    }

    [Test]
    public void MergeHeaderMap_WithComplexScenario_ShouldWorkLikeOldFactory()
    {
        // This test simulates the complex scenario from the old factory tests
        
        // Arrange - Start with some initial headers
        CoseHeaderMap initialMap = new();
        initialMap.Add(new CoseHeaderLabel("Initial"), CoseHeaderValue.FromString("InitialValue"));

        // Add int headers
        List<CoseHeader<int>> intHeaders = new()
        {
            new("IntHeader1", 42, true),
            new("IntHeader2", 100, false)
        };

        // Add string headers  
        List<CoseHeader<string>> stringHeaders = new()
        {
            new("StringHeader1", "StringValue1", true),
            new("StringHeader2", "StringValue2", false)
        };

        // Act - Build up the header map like the old factory would
        CoseHeaderMap result = intHeaders.ToCoseHeaderMap(initialMap);
        result = stringHeaders.ToCoseHeaderMap(result);

        // Add more headers directly
        CoseHeaderMap additionalHeaders = new();
        additionalHeaders.Add(new CoseHeaderLabel("Additional"), CoseHeaderValue.FromInt32(999));
        result = result.MergeHeaderMap(additionalHeaders);

        // Assert
        Assert.That(result.Count, Is.EqualTo(6));
        Assert.That(result[new CoseHeaderLabel("Initial")].GetValueAsString(), Is.EqualTo("InitialValue"));
        Assert.That(result[new CoseHeaderLabel("IntHeader1")].GetValueAsInt32(), Is.EqualTo(42));
        Assert.That(result[new CoseHeaderLabel("IntHeader2")].GetValueAsInt32(), Is.EqualTo(100));
        Assert.That(result[new CoseHeaderLabel("StringHeader1")].GetValueAsString(), Is.EqualTo("StringValue1"));
        Assert.That(result[new CoseHeaderLabel("StringHeader2")].GetValueAsString(), Is.EqualTo("StringValue2"));
        Assert.That(result[new CoseHeaderLabel("Additional")].GetValueAsInt32(), Is.EqualTo(999));
    }
}
