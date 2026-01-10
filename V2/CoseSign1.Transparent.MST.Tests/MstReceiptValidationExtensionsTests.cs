// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using Moq;

[TestFixture]
public class MstReceiptValidationExtensionsTests
{
    [Test]
    public void AddMstReceiptAssertionProvider_WithClient_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;

        var builder = Cose.Sign1Message();

        var result = builder.AddMstReceiptAssertionProvider(b => b.UseClient(client));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithProvider_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;
        var provider = new MstTransparencyProvider(client);

        var builder = Cose.Sign1Message();

        var result = builder.AddMstReceiptAssertionProvider(b => b.UseProvider(provider));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithVerificationOptions_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;
        var options = new CodeTransparencyVerificationOptions();

        var builder = Cose.Sign1Message();

        var result = builder.AddMstReceiptAssertionProvider(b => b
            .UseClient(client)
            .WithVerificationOptions(options));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithVerificationOptionsWithoutClientOrProvider_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<InvalidOperationException>(() => builder.AddMstReceiptAssertionProvider(b => b
            .WithVerificationOptions(new CodeTransparencyVerificationOptions())));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithNoConfiguration_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<InvalidOperationException>(() => builder.AddMstReceiptAssertionProvider(_ => { }));
    }
}
