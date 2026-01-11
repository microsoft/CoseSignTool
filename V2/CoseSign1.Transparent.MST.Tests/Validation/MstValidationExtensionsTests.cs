// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Validation;

using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation.Interfaces;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="MstValidationExtensions"/>.
/// </summary>
[TestFixture]
[Category("MST")]
[Category("Validation")]
public class MstValidationExtensionsTests
{
    private Mock<ICoseSign1ValidationBuilder> _mockBuilder = null!;

    [SetUp]
    public void SetUp()
    {
        _mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        _mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>())).Returns(_mockBuilder.Object);
    }

    #region ValidateMst Tests

    [Test]
    public void ValidateMst_WithNullBuilder_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            ((ICoseSign1ValidationBuilder)null!).ValidateMst(m => m.RequireReceiptPresence()));
        Assert.That(ex!.ParamName, Is.EqualTo("builder"));
    }

    [Test]
    public void ValidateMst_WithNullConfigure_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("configure"));
    }

    [Test]
    public void ValidateMst_WithRequireReceiptPresence_AddsComponent()
    {
        // Act
        var result = _mockBuilder.Object.ValidateMst(m => m.RequireReceiptPresence());

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
        _mockBuilder.Verify(b => b.AddComponent(It.IsAny<MstReceiptPresenceAssertionProvider>()), Times.Once);
    }

    [Test]
    public void ValidateMst_WithVerifyReceiptWithClient_AddsComponent()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();

        // Act
        var result = _mockBuilder.Object.ValidateMst(m => m.VerifyReceipt(mockClient.Object));

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
        _mockBuilder.Verify(b => b.AddComponent(It.IsAny<MstReceiptAssertionProvider>()), Times.Once);
    }

    [Test]
    public void ValidateMst_WithVerifyReceiptWithProvider_AddsComponent()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();
        var provider = new MstTransparencyProvider(mockClient.Object);

        // Act
        var result = _mockBuilder.Object.ValidateMst(m => m.VerifyReceipt(provider));

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
        _mockBuilder.Verify(b => b.AddComponent(It.IsAny<MstReceiptAssertionProvider>()), Times.Once);
    }

    [Test]
    public void ValidateMst_WithVerifyReceiptOnline_AddsComponent()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();

        // Act
        var result = _mockBuilder.Object.ValidateMst(m => m.VerifyReceiptOnline(mockClient.Object, "example.com"));

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
        _mockBuilder.Verify(b => b.AddComponent(It.IsAny<MstReceiptOnlineAssertionProvider>()), Times.Once);
    }

    [Test]
    public void ValidateMst_WithMultipleValidators_AddsAllComponents()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();
        var addedComponents = new List<IValidationComponent>();
        _mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(_mockBuilder.Object);

        // Act
        var result = _mockBuilder.Object.ValidateMst(m => m
            .RequireReceiptPresence()
            .VerifyReceipt(mockClient.Object));

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
        Assert.That(addedComponents, Has.Count.EqualTo(2));
        Assert.That(addedComponents.Any(c => c is MstReceiptPresenceAssertionProvider), Is.True);
        Assert.That(addedComponents.Any(c => c is MstReceiptAssertionProvider), Is.True);
    }

    [Test]
    public void ValidateMst_WithNoValidatorsConfigured_ThrowsInvalidOperationException()
    {
        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _mockBuilder.Object.ValidateMst(m => { }));
        Assert.That(ex!.Message, Does.Contain("No MST validators configured"));
    }

    [Test]
    public void ValidateMst_ReturnsSameBuilderInstance()
    {
        // Act
        var result = _mockBuilder.Object.ValidateMst(m => m.RequireReceiptPresence());

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
    }

    #endregion

    #region AddMstValidator (Obsolete) Tests

#pragma warning disable CS0618 // Type or member is obsolete
    [Test]
    public void AddMstValidator_WithNullBuilder_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            ((ICoseSign1ValidationBuilder)null!).AddMstValidator(m => m.RequireReceiptPresence()));
        Assert.That(ex!.ParamName, Is.EqualTo("builder"));
    }

    [Test]
    public void AddMstValidator_WithNullConfigure_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.AddMstValidator(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("configure"));
    }

    [Test]
    public void AddMstValidator_CallsValidateMst()
    {
        // Act
        var result = _mockBuilder.Object.AddMstValidator(m => m.RequireReceiptPresence());

        // Assert
        Assert.That(result, Is.SameAs(_mockBuilder.Object));
        _mockBuilder.Verify(b => b.AddComponent(It.IsAny<MstReceiptPresenceAssertionProvider>()), Times.Once);
    }
#pragma warning restore CS0618

    #endregion

    #region Builder.VerifyReceipt(client) Tests

    [Test]
    public void VerifyReceipt_WithNullClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(m => m.VerifyReceipt((CodeTransparencyClient)null!)));
        Assert.That(ex!.ParamName, Is.EqualTo("client"));
    }

    #endregion

    #region Builder.VerifyReceipt(provider) Tests

    [Test]
    public void VerifyReceipt_WithNullProvider_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(m => m.VerifyReceipt((MstTransparencyProvider)null!)));
        Assert.That(ex!.ParamName, Is.EqualTo("provider"));
    }

    #endregion

    #region Builder.VerifyReceiptOnline Tests

    [Test]
    public void VerifyReceiptOnline_WithNullClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(m => m.VerifyReceiptOnline(null!, "example.com")));
        Assert.That(ex!.ParamName, Is.EqualTo("client"));
    }

    [Test]
    public void VerifyReceiptOnline_WithNullIssuerHost_ThrowsArgumentNullException()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(m => m.VerifyReceiptOnline(mockClient.Object, null!)));
        Assert.That(ex!.ParamName, Is.EqualTo("issuerHost"));
    }

    [Test]
    public void VerifyReceiptOnline_WithEmptyIssuerHost_ThrowsArgumentNullException()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(m => m.VerifyReceiptOnline(mockClient.Object, "")));
        Assert.That(ex!.ParamName, Is.EqualTo("issuerHost"));
    }

    [Test]
    public void VerifyReceiptOnline_WithWhitespaceIssuerHost_ThrowsArgumentNullException()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            _mockBuilder.Object.ValidateMst(m => m.VerifyReceiptOnline(mockClient.Object, "   ")));
        Assert.That(ex!.ParamName, Is.EqualTo("issuerHost"));
    }

    #endregion

    #region Builder.RequireReceiptPresence Tests

    [Test]
    public void RequireReceiptPresence_AddsPresenceValidator()
    {
        // Arrange
        IValidationComponent? addedComponent = null;
        _mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponent = c)
            .Returns(_mockBuilder.Object);

        // Act
        _mockBuilder.Object.ValidateMst(m => m.RequireReceiptPresence());

        // Assert
        Assert.That(addedComponent, Is.InstanceOf<MstReceiptPresenceAssertionProvider>());
    }

    [Test]
    public void RequireReceiptPresence_CanBeChained()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();
        var addedComponents = new List<IValidationComponent>();
        _mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(_mockBuilder.Object);

        // Act
        _mockBuilder.Object.ValidateMst(m => m
            .RequireReceiptPresence()
            .VerifyReceipt(mockClient.Object)
            .RequireReceiptPresence()); // Adding again should be allowed

        // Assert
        Assert.That(addedComponents.Count(c => c is MstReceiptPresenceAssertionProvider), Is.EqualTo(2));
    }

    #endregion

    #region Builder Returns IMstValidatorBuilder Tests

    [Test]
    public void Builder_Methods_ReturnSameBuilderInstance_ForChaining()
    {
        // Arrange
        var mockClient = new Mock<CodeTransparencyClient>();

        // Act - verify all methods return IMstValidatorBuilder for chaining
        Assert.DoesNotThrow(() =>
            _mockBuilder.Object.ValidateMst(m =>
            {
                var b1 = m.RequireReceiptPresence();
                var b2 = m.VerifyReceipt(mockClient.Object);
                var b3 = m.VerifyReceipt(new MstTransparencyProvider(mockClient.Object));
                var b4 = m.VerifyReceiptOnline(mockClient.Object, "test.com");

                Assert.That(b1, Is.SameAs(m));
                Assert.That(b2, Is.SameAs(m));
                Assert.That(b3, Is.SameAs(m));
                Assert.That(b4, Is.SameAs(m));
            }));
    }

    #endregion
}
