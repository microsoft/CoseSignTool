// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

/// <summary>
/// Tests for ExitCode enumeration.
/// </summary>
[TestFixture]
public class ExitCodeTests
{
    [Test]
    public void ExitCode_Success_ShouldBeZero()
    {
        // Arrange & Act
        var exitCode = ExitCode.Success;

        // Assert
        Assert.That((int)exitCode, Is.EqualTo(0));
    }

    [Test]
    public void ExitCode_GeneralError_ShouldBeOne()
    {
        // Arrange & Act
        var exitCode = ExitCode.GeneralError;

        // Assert
        Assert.That((int)exitCode, Is.EqualTo(1));
    }

    [Test]
    public void ExitCode_InvalidArguments_ShouldBeTwo()
    {
        // Arrange & Act
        var exitCode = ExitCode.InvalidArguments;

        // Assert
        Assert.That((int)exitCode, Is.EqualTo(2));
    }

    [Test]
    public void ExitCode_FileNotFound_ShouldBeThree()
    {
        // Arrange & Act
        var exitCode = ExitCode.FileNotFound;

        // Assert
        Assert.That((int)exitCode, Is.EqualTo(3));
    }

    [Test]
    public void ExitCode_CertificateNotFound_ShouldBeFour()
    {
        // Arrange & Act
        var exitCode = ExitCode.CertificateNotFound;

        // Assert
        Assert.That((int)exitCode, Is.EqualTo(4));
    }

    [TestCase(ExitCode.SigningFailed, 10)]
    [TestCase(ExitCode.ValidationFailed, 20)]
    [TestCase(ExitCode.InvalidSignature, 21)]
    [TestCase(ExitCode.VerificationFailed, 22)]
    [TestCase(ExitCode.CertificateExpired, 23)]
    [TestCase(ExitCode.UntrustedCertificate, 24)]
    [TestCase(ExitCode.PluginError, 30)]
    [TestCase(ExitCode.InspectionFailed, 40)]
    public void ExitCode_AllCodes_ShouldHaveExpectedValues(ExitCode code, int expectedValue)
    {
        // Assert
        Assert.That((int)code, Is.EqualTo(expectedValue));
    }

    [Test]
    public void ExitCode_AllValues_ShouldBeUnique()
    {
        // Arrange
        var allValues = Enum.GetValues<ExitCode>().Cast<int>().ToList();

        // Assert
        Assert.That(allValues.Distinct().Count(), Is.EqualTo(allValues.Count));
    }

    [Test]
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
        foreach (var expected in expectedCodes)
        {
            Assert.That(actualCodes, Does.Contain(expected));
        }
    }

    [Test]
    public void ExitCode_CanBeCastToInt()
    {
        // Arrange
        ExitCode code = ExitCode.Success;

        // Act
        int value = (int)code;

        // Assert
        Assert.That(value, Is.EqualTo(0));
    }

    [Test]
    public void ExitCode_CanBeCastFromInt()
    {
        // Arrange
        int value = 10;

        // Act
        ExitCode code = (ExitCode)value;

        // Assert
        Assert.That(code, Is.EqualTo(ExitCode.SigningFailed));
    }
}