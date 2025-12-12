// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

/// <summary>
/// Tests for ExitCode enumeration.
/// </summary>
public class ExitCodeTests
{
    [Fact]
    public void ExitCode_Success_ShouldBeZero()
    {
        // Arrange & Act
        var exitCode = ExitCode.Success;

        // Assert
        exitCode.Should().Be(0);
        ((int)exitCode).Should().Be(0);
    }

    [Fact]
    public void ExitCode_GeneralError_ShouldBeOne()
    {
        // Arrange & Act
        var exitCode = ExitCode.GeneralError;

        // Assert
        exitCode.Should().Be((ExitCode)1);
        ((int)exitCode).Should().Be(1);
    }

    [Fact]
    public void ExitCode_InvalidArguments_ShouldBeTwo()
    {
        // Arrange & Act
        var exitCode = ExitCode.InvalidArguments;

        // Assert
        ((int)exitCode).Should().Be(2);
    }

    [Fact]
    public void ExitCode_FileNotFound_ShouldBeThree()
    {
        // Arrange & Act
        var exitCode = ExitCode.FileNotFound;

        // Assert
        ((int)exitCode).Should().Be(3);
    }

    [Fact]
    public void ExitCode_CertificateNotFound_ShouldBeFour()
    {
        // Arrange & Act
        var exitCode = ExitCode.CertificateNotFound;

        // Assert
        ((int)exitCode).Should().Be(4);
    }

    [Theory]
    [InlineData(ExitCode.SigningFailed, 10)]
    [InlineData(ExitCode.ValidationFailed, 20)]
    [InlineData(ExitCode.InvalidSignature, 21)]
    [InlineData(ExitCode.VerificationFailed, 22)]
    [InlineData(ExitCode.CertificateExpired, 23)]
    [InlineData(ExitCode.UntrustedCertificate, 24)]
    [InlineData(ExitCode.PluginError, 30)]
    [InlineData(ExitCode.InspectionFailed, 40)]
    public void ExitCode_AllCodes_ShouldHaveExpectedValues(ExitCode code, int expectedValue)
    {
        // Assert
        ((int)code).Should().Be(expectedValue);
    }

    [Fact]
    public void ExitCode_AllValues_ShouldBeUnique()
    {
        // Arrange
        var allValues = Enum.GetValues<ExitCode>().Cast<int>().ToList();

        // Assert
        allValues.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void ExitCode_ShouldHaveAllDocumentedCodes()
    {
        // Arrange
        var expectedCodes = new[]
        {
            ExitCode.Success,
            ExitCode.GeneralError,
            ExitCode.InvalidArguments,
            ExitCode.FileNotFound,
            ExitCode.CertificateNotFound,
            ExitCode.SigningFailed,
            ExitCode.ValidationFailed,
            ExitCode.InvalidSignature,
            ExitCode.CertificateExpired,
            ExitCode.UntrustedCertificate,
            ExitCode.PluginError
        };

        // Act
        var actualCodes = Enum.GetValues<ExitCode>();

        // Assert
        actualCodes.Should().Contain(expectedCodes);
    }

    [Fact]
    public void ExitCode_CanBeCastToInt()
    {
        // Arrange
        ExitCode code = ExitCode.Success;

        // Act
        int value = (int)code;

        // Assert
        value.Should().Be(0);
    }

    [Fact]
    public void ExitCode_CanBeCastFromInt()
    {
        // Arrange
        int value = 10;

        // Act
        ExitCode code = (ExitCode)value;

        // Assert
        code.Should().Be(ExitCode.SigningFailed);
    }
}
