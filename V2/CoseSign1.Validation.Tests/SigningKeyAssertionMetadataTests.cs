// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Results;

[TestFixture]
public class SigningKeyAssertionMetadataTests
{
    [Test]
    public void GetAssertionSetOrEmpty_WithNullResult_ReturnsEmpty()
    {
        Assert.That(SigningKeyAssertionMetadata.GetAssertionSetOrEmpty(null!).Assertions, Is.Empty);
    }

    [Test]
    public void GetAssertionSetOrEmpty_WithNullMetadata_ReturnsEmpty()
    {
        var result = new ValidationResult
        {
            Kind = ValidationResultKind.Success,
            ValidatorName = "v",
            Metadata = null!
        };

        Assert.That(SigningKeyAssertionMetadata.GetAssertionSetOrEmpty(result).Assertions, Is.Empty);
    }

    [Test]
    public void GetAssertionSetOrEmpty_WithMissingKey_ReturnsEmpty()
    {
        var result = ValidationResult.Success("v", new Dictionary<string, object>());
        Assert.That(SigningKeyAssertionMetadata.GetAssertionSetOrEmpty(result).Assertions, Is.Empty);
    }

    [Test]
    public void GetAssertionSetOrEmpty_WithListValue_ReturnsList()
    {
        var assertions = new List<SigningKeyAssertion>
        {
            new("a", true),
            new("b", false, "x")
        };

        var result = ValidationResult.Success("v", new Dictionary<string, object>
        {
            [SigningKeyAssertionMetadata.AssertionsKey] = assertions
        });

        var actual = SigningKeyAssertionMetadata.GetAssertionSetOrEmpty(result).Assertions;
        Assert.That(actual, Has.Count.EqualTo(2));
        Assert.That(actual[0].ClaimId, Is.EqualTo("a"));
    }

    [Test]
    public void GetAssertionSetOrEmpty_WithEnumerableValue_ReturnsMaterializedList()
    {
        IEnumerable<SigningKeyAssertion> assertions = new[]
        {
            new SigningKeyAssertion("a", true)
        }.Where(a => a.AsBool == true);

        var result = ValidationResult.Success("v", new Dictionary<string, object>
        {
            [SigningKeyAssertionMetadata.AssertionsKey] = assertions
        });

        var actual = SigningKeyAssertionMetadata.GetAssertionSetOrEmpty(result).Assertions;
        Assert.That(actual, Has.Count.EqualTo(1));
        Assert.That(actual[0].ClaimId, Is.EqualTo("a"));
    }

    [Test]
    public void GetAssertionSetOrEmpty_WithWrongType_ReturnsEmpty()
    {
        var result = ValidationResult.Success("v", new Dictionary<string, object>
        {
            [SigningKeyAssertionMetadata.AssertionsKey] = 123
        });

        Assert.That(SigningKeyAssertionMetadata.GetAssertionSetOrEmpty(result).Assertions, Is.Empty);
    }
}
