// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Interfaces;

[TestFixture]
[Category("Validation")]
public class ToBeSignedAttestationResultTests
{
    [Test]
    public void NotAttested_ReturnsNotAttestedResult()
    {
        ToBeSignedAttestationResult result = ToBeSignedAttestationResult.NotAttested("TestProvider", "not available");

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAttested, Is.False);
            Assert.That(result.Provider, Is.EqualTo("TestProvider"));
            Assert.That(result.Details, Is.EqualTo("not available"));
        });
    }

    [Test]
    public void Attested_ReturnsAttestedResult()
    {
        ToBeSignedAttestationResult result = ToBeSignedAttestationResult.Attested("TestProvider", "validated");

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAttested, Is.True);
            Assert.That(result.Provider, Is.EqualTo("TestProvider"));
            Assert.That(result.Details, Is.EqualTo("validated"));
        });
    }

    [Test]
    public void NotAttested_WithNullDetails_DetailsIsNull()
    {
        ToBeSignedAttestationResult result = ToBeSignedAttestationResult.NotAttested("P");

        Assert.That(result.Details, Is.Null);
    }
}
