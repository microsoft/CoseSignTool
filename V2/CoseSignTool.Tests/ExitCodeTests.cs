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
        Assert.Equal(0, (int)exitCode);
    }

    [Fact]
    public void ExitCode_GeneralError_ShouldBeOne()
    {
        // Arrange & Act
        var exitCode = ExitCode.GeneralError;

        // Assert
        Assert.Equal(1, (int)exitCode);
    }

    [Fact]
    public void ExitCode_InvalidArguments_ShouldBeTwo()
    {
        // Arrange & Act
        var exitCode = ExitCode.InvalidArguments;

        // Assert
        Assert.Equal(2, (int)exitCode);
    }

    [Fact]
    public void ExitCode_FileNotFound_ShouldBeThree()
    {
        // Arrange & Act
        var exitCode = ExitCode.FileNotFound;

        // Assert
        Assert.Equal(3, (int)exitCode);
    }

    [Fact]
    public void ExitCode_CertificateNotFound_ShouldBeFour()
    {
        // Arrange & Act
        var exitCode = ExitCode.CertificateNotFound;

        // Assert
        Assert.Equal(4, (int)exitCode);
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
        Assert.Equal(expectedValue, (int)code);
    }

    [Fact]
    public void ExitCode_AllValues_ShouldBeUnique()
    {
        // Arrange
        var allValues = Enum.GetValues<ExitCode>().Cast<int>().ToList();

        // Assert
        Assert.Equal(allValues.Count, allValues.Distinct().Count());
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
        Assert.All(expectedCodes, expected => Assert.Contains(expected, actualCodes));
    }

    [Fact]
    public void ExitCode_CanBeCastToInt()
    {
        // Arrange
        ExitCode code = ExitCode.Success;

        // Act
        int value = (int)code;

        // Assert
        Assert.Equal(0, value);
    }

    [Fact]
    public void ExitCode_CanBeCastFromInt()
    {
        // Arrange
        int value = 10;

        // Act
        ExitCode code = (ExitCode)value;

        // Assert
        Assert.Equal(ExitCode.SigningFailed, code);
    }
}
