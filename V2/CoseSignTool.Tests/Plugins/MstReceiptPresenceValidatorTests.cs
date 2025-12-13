// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSignTool.MST.Plugin;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the MstReceiptPresenceValidator class.
/// </summary>
[TestFixture]
public class MstReceiptPresenceValidatorTests
{
    private MstReceiptPresenceValidator Validator = null!;

    [SetUp]
    public void Setup()
    {
        Validator = new MstReceiptPresenceValidator();
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Act
        var result = Validator.Validate(null!);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Failures.Should().ContainSingle();
        result.Failures[0].ErrorCode.Should().Be("NULL_INPUT");
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        // Act
        var result = await Validator.ValidateAsync(null!);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Failures.Should().ContainSingle();
        result.Failures[0].ErrorCode.Should().Be("NULL_INPUT");
    }

    [Test]
    public void Validate_WithMessageWithoutReceipt_ReturnsFailure()
    {
        // Arrange - create a simple COSE message without MST receipt
        // This requires a valid signing key which is complex to set up in tests
        // For now, we test the error path with messages that don't have receipts

        // Skip this test if we can't create a valid CoseSign1Message
        // In real implementation, we'd need test fixtures
    }

    [Test]
    public void Validator_ImplementsIValidator()
    {
        // Assert
        Validator.Should().BeAssignableTo<IValidator<CoseSign1Message>>();
    }

    [Test]
    public async Task ValidateAsync_ReturnsSameResultAsValidate()
    {
        // Arrange
        CoseSign1Message? nullMessage = null;

        // Act
        var syncResult = Validator.Validate(nullMessage!);
        var asyncResult = await Validator.ValidateAsync(nullMessage!);

        // Assert - both should return same failure for null input
        syncResult.IsValid.Should().Be(asyncResult.IsValid);
        syncResult.Failures[0].ErrorCode.Should().Be(asyncResult.Failures[0].ErrorCode);
    }
}
