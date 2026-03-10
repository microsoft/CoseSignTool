// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Results;

/// <summary>
/// Tests for <see cref="CoseSign1ValidationResult"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CoseSign1ValidationResultTests
{
    [Test]
    public void Constructor_SetsAllProperties()
    {
        var resolution = ValidationResult.Success("Resolution");
        var trust = ValidationResult.Success("Trust");
        var signature = ValidationResult.Success("Signature");
        var postSignature = ValidationResult.Success("PostSignature");
        var overall = ValidationResult.Success("Overall");

        var result = new CoseSign1ValidationResult(resolution, trust, signature, postSignature, overall);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution, Is.SameAs(resolution));
            Assert.That(result.Trust, Is.SameAs(trust));
            Assert.That(result.Signature, Is.SameAs(signature));
            Assert.That(result.PostSignaturePolicy, Is.SameAs(postSignature));
            Assert.That(result.Overall, Is.SameAs(overall));
        });
    }

    [Test]
    public void Resolution_ReturnsCorrectResult()
    {
        var resolution = ValidationResult.Success("Resolution");
        var result = CreateResult(resolution: resolution);

        Assert.That(result.Resolution.ValidatorName, Is.EqualTo("Resolution"));
    }

    [Test]
    public void Trust_ReturnsCorrectResult()
    {
        var trust = ValidationResult.Success("Trust");
        var result = CreateResult(trust: trust);

        Assert.That(result.Trust.ValidatorName, Is.EqualTo("Trust"));
    }

    [Test]
    public void Signature_ReturnsCorrectResult()
    {
        var signature = ValidationResult.Success("Signature");
        var result = CreateResult(signature: signature);

        Assert.That(result.Signature.ValidatorName, Is.EqualTo("Signature"));
    }

    [Test]
    public void PostSignaturePolicy_ReturnsCorrectResult()
    {
        var postSignature = ValidationResult.Success("PostSignature");
        var result = CreateResult(postSignature: postSignature);

        Assert.That(result.PostSignaturePolicy.ValidatorName, Is.EqualTo("PostSignature"));
    }

    [Test]
    public void Overall_ReturnsCorrectResult()
    {
        var overall = ValidationResult.Success("Overall");
        var result = CreateResult(overall: overall);

        Assert.That(result.Overall.ValidatorName, Is.EqualTo("Overall"));
    }

    [Test]
    public void AllStagesSuccessful_OverallIsSuccess()
    {
        var result = new CoseSign1ValidationResult(
            ValidationResult.Success("R"),
            ValidationResult.Success("T"),
            ValidationResult.Success("S"),
            ValidationResult.Success("P"),
            ValidationResult.Success("O"));

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsSuccess, Is.True);
            Assert.That(result.Trust.IsSuccess, Is.True);
            Assert.That(result.Signature.IsSuccess, Is.True);
            Assert.That(result.PostSignaturePolicy.IsSuccess, Is.True);
            Assert.That(result.Overall.IsSuccess, Is.True);
        });
    }

    [Test]
    public void FailedResolution_OverallIsFailure()
    {
        var resolution = ValidationResult.Failure("R", "Failed");
        var result = CreateResult(resolution: resolution, overall: resolution);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void FailedTrust_OverallIsFailure()
    {
        var trust = ValidationResult.Failure("T", "Failed");
        var result = CreateResult(trust: trust, overall: trust);

        Assert.Multiple(() =>
        {
            Assert.That(result.Trust.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void FailedSignature_OverallIsFailure()
    {
        var signature = ValidationResult.Failure("S", "Failed");
        var result = CreateResult(signature: signature, overall: signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.Signature.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void FailedPostSignature_OverallIsFailure()
    {
        var postSignature = ValidationResult.Failure("P", "Failed");
        var result = CreateResult(postSignature: postSignature, overall: postSignature);

        Assert.Multiple(() =>
        {
            Assert.That(result.PostSignaturePolicy.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void NotApplicableStages_AreRecorded()
    {
        var result = new CoseSign1ValidationResult(
            ValidationResult.Failure("R", "Failed"),
            ValidationResult.NotApplicable("T"),
            ValidationResult.NotApplicable("S"),
            ValidationResult.NotApplicable("P"),
            ValidationResult.Failure("O", "Failed"));

        Assert.Multiple(() =>
        {
            Assert.That(result.Trust.IsNotApplicable, Is.True);
            Assert.That(result.Signature.IsNotApplicable, Is.True);
            Assert.That(result.PostSignaturePolicy.IsNotApplicable, Is.True);
        });
    }

    private static CoseSign1ValidationResult CreateResult(
        ValidationResult? resolution = null,
        ValidationResult? trust = null,
        ValidationResult? signature = null,
        ValidationResult? postSignature = null,
        ValidationResult? overall = null)
    {
        return new CoseSign1ValidationResult(
            resolution ?? ValidationResult.Success("R"),
            trust ?? ValidationResult.Success("T"),
            signature ?? ValidationResult.Success("S"),
            postSignature ?? ValidationResult.Success("P"),
            overall ?? ValidationResult.Success("O"));
    }
}
