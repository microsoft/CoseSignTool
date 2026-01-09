// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

using Azure.Identity;
using CoseSign1.AzureKeyVault.Validation;

[TestFixture]
public class AzureKeyVaultValidationExtensionsTests
{
    [Test]
    public void ValidateAzureKeyVault_WithDetachedPayloadByteArray_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();

        var detached = new byte[] { 1, 2, 3 };
        var result = builder.ValidateAzureKeyVault(detached, _ => { });

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateAzureKeyVault_WithDetachedPayloadReadOnlyMemory_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();

        ReadOnlyMemory<byte> detached = new byte[] { 1, 2, 3 };
        var result = builder.ValidateAzureKeyVault(detached, _ => { });

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateAzureKeyVault_WithFluentConfig_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();

        var result = builder.ValidateAzureKeyVault(akv => akv
            .WithDetachedPayload(new byte[] { 1, 2, 3 })
            .RequireAzureKey()
            .AllowOnlineVerify());

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateAzureKeyVault_WithCredential_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        var credential = new DefaultAzureCredential();

        var result = builder.ValidateAzureKeyVault(akv => akv
            .AllowOnlineVerify()
            .WithCredential(credential));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateAzureKeyVault_WithNullBuilder_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AzureKeyVaultValidationExtensions.ValidateAzureKeyVault(null!, _ => { }));
    }

    [Test]
    public void ValidateAzureKeyVault_WithNullConfigure_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.ValidateAzureKeyVault(null!));
    }

    [Test]
    public void ValidateAzureKeyVault_WithNullDetachedPayload_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.ValidateAzureKeyVault((byte[])null!, _ => { }));
    }

    [Test]
    public void ValidateAzureKeyVault_WithNullCredential_ThrowsArgumentNullException()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        Assert.Throws<ArgumentNullException>(() => builder.ValidateAzureKeyVault(akv => akv.WithCredential(null!)));
    }

    #region Legacy API Tests

#pragma warning disable CS0618 // Type or member is obsolete - testing legacy API
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
#pragma warning restore CS0618

    #endregion
}
