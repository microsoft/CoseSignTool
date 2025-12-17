// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using Moq;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstReceiptValidationExtensionsTests
{
    [Test]
    public void AddMstReceiptValidator_WithClient_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;

        var builder = Cose.Sign1Message();

        var result = builder.AddMstReceiptValidator(b => b.UseClient(client));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstReceiptValidator_WithProvider_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;
        var provider = new MstTransparencyProvider(client);

        var builder = Cose.Sign1Message();

        var result = builder.AddMstReceiptValidator(b => b.UseProvider(provider));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstReceiptValidator_WithVerificationOptions_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;
        var options = new CodeTransparencyVerificationOptions();

        var builder = Cose.Sign1Message();

        var result = builder.AddMstReceiptValidator(b => b
            .UseClient(client)
            .WithVerificationOptions(options));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstReceiptValidator_WithVerificationOptionsWithoutClientOrProvider_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<InvalidOperationException>(() => builder.AddMstReceiptValidator(b => b
            .WithVerificationOptions(new CodeTransparencyVerificationOptions())));
    }

    [Test]
    public void AddMstReceiptValidator_WithNoConfiguration_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<InvalidOperationException>(() => builder.AddMstReceiptValidator(_ => { }));
    }
}
