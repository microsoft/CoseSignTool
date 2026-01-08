// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation.Results;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class TrustAssertionMetadataTests
{
    [Test]
    public void GetAssertionsOrEmpty_WithNullResult_ReturnsEmpty()
    {
        Assert.That(TrustAssertionMetadata.GetAssertionsOrEmpty(null!), Is.Empty);
    }

    [Test]
    public void GetAssertionsOrEmpty_WithNullMetadata_ReturnsEmpty()
    {
        var result = new ValidationResult
        {
            Kind = ValidationResultKind.Success,
            ValidatorName = "v",
            Metadata = null!
        };

        Assert.That(TrustAssertionMetadata.GetAssertionsOrEmpty(result), Is.Empty);
    }

    [Test]
    public void GetAssertionsOrEmpty_WithMissingKey_ReturnsEmpty()
    {
        var result = ValidationResult.Success("v", new Dictionary<string, object>());
        Assert.That(TrustAssertionMetadata.GetAssertionsOrEmpty(result), Is.Empty);
    }

    [Test]
    public void GetAssertionsOrEmpty_WithListValue_ReturnsList()
    {
        var assertions = new List<TrustAssertion>
        {
            new("a", true),
            new("b", false, "x")
        };

        var result = ValidationResult.Success("v", new Dictionary<string, object>
        {
            [TrustAssertionMetadata.AssertionsKey] = assertions
        });

        var actual = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(actual, Has.Count.EqualTo(2));
        Assert.That(actual[0].ClaimId, Is.EqualTo("a"));
    }

    [Test]
    public void GetAssertionsOrEmpty_WithEnumerableValue_ReturnsMaterializedList()
    {
        IEnumerable<TrustAssertion> assertions = new[]
        {
            new TrustAssertion("a", true)
        }.Where(a => a.Satisfied);

        var result = ValidationResult.Success("v", new Dictionary<string, object>
        {
            [TrustAssertionMetadata.AssertionsKey] = assertions
        });

        var actual = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(actual, Has.Count.EqualTo(1));
        Assert.That(actual[0].ClaimId, Is.EqualTo("a"));
    }

    [Test]
    public void GetAssertionsOrEmpty_WithWrongType_ReturnsEmpty()
    {
        var result = ValidationResult.Success("v", new Dictionary<string, object>
        {
            [TrustAssertionMetadata.AssertionsKey] = 123
        });

        Assert.That(TrustAssertionMetadata.GetAssertionsOrEmpty(result), Is.Empty);
    }
}
