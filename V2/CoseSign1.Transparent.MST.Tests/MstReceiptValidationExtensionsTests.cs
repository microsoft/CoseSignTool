// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation.Interfaces;
using Moq;

[TestFixture]
public class MstReceiptValidationExtensionsTests
{
    [Test]
    public void AddMstReceiptAssertionProvider_WithClient_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;

        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);

        var result = builder.Object.AddMstReceiptAssertionProvider(b => b.UseClient(client));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithProvider_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;
        var provider = new MstTransparencyProvider(client);

        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);

        var result = builder.Object.AddMstReceiptAssertionProvider(b => b.UseProvider(provider));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithVerificationOptions_AddsValidator()
    {
        var client = new Mock<CodeTransparencyClient>().Object;
        var options = new CodeTransparencyVerificationOptions();

        var builder = new Mock<ICoseSign1ValidationBuilder>();
        builder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(builder.Object);

        var result = builder.Object.AddMstReceiptAssertionProvider(b => b
            .UseClient(client)
            .WithVerificationOptions(options));

        Assert.That(result, Is.SameAs(builder.Object));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithVerificationOptionsWithoutClientOrProvider_Throws()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();

        Assert.Throws<InvalidOperationException>(() => builder.Object.AddMstReceiptAssertionProvider(b => b
            .WithVerificationOptions(new CodeTransparencyVerificationOptions())));
    }

    [Test]
    public void AddMstReceiptAssertionProvider_WithNoConfiguration_Throws()
    {
        var builder = new Mock<ICoseSign1ValidationBuilder>();

        Assert.Throws<InvalidOperationException>(() => builder.Object.AddMstReceiptAssertionProvider(_ => { }));
    }
}
