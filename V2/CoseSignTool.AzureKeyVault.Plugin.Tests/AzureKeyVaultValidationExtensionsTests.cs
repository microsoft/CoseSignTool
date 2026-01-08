// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.AzureKeyVault.Validation;

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

[TestFixture]
public class AzureKeyVaultValidationExtensionsTests
{
    [Test]
    public void AddAzureKeyVaultSignatureValidator_WithDetachedPayload_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();

        var detached = new byte[] { 1, 2, 3 };
        var result = builder.AddAzureKeyVaultSignatureValidator(b => b.WithDetachedPayload(detached));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddAzureKeyVaultSignatureValidator_WithoutDetachedPayload_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();

        var detached = new byte[] { 1, 2, 3 };
        var result = builder.AddAzureKeyVaultSignatureValidator(b =>
        {
            b.WithDetachedPayload(detached);
            b.WithoutDetachedPayload();
        });

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddAzureKeyVaultSignatureValidator_WithNullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultValidationExtensions.AddAzureKeyVaultSignatureValidator(null!, _ => { }));
    }

    [Test]
    public void AddAzureKeyVaultSignatureValidator_WithNullConfigure_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.AddAzureKeyVaultSignatureValidator(null!));
    }
}
