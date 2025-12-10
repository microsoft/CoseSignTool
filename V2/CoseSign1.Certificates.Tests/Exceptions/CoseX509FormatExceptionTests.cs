// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Exceptions;

namespace CoseSign1.Certificates.Tests.Exceptions;

[TestFixture]
public class CoseX509FormatExceptionTests
{
    [Test]
    public void DefaultConstructor_SetsDefaultMessage()
    {
        // Act
        var exception = new CoseX509FormatException();

        // Assert
        Assert.That(exception.Message, Is.EqualTo("Failed to meet COSE X509 format requirements."));
        Assert.That(exception.InnerException, Is.Null);
    }

    [Test]
    public void MessageConstructor_SetsProvidedMessage()
    {
        // Arrange
        string message = "Custom error message";

        // Act
        var exception = new CoseX509FormatException(message);

        // Assert
        Assert.That(exception.Message, Is.EqualTo(message));
        Assert.That(exception.InnerException, Is.Null);
    }

    [Test]
    public void MessageAndInnerExceptionConstructor_SetsBothProperties()
    {
        // Arrange
        string message = "Custom error message";
        var innerException = new InvalidOperationException("Inner error");

        // Act
        var exception = new CoseX509FormatException(message, innerException);

        // Assert
        Assert.That(exception.Message, Is.EqualTo(message));
        Assert.That(exception.InnerException, Is.SameAs(innerException));
    }

    [Test]
    public void Exception_CanBeThrown()
    {
        // Act & Assert
        Assert.Throws<CoseX509FormatException>(() => throw new CoseX509FormatException());
    }

    [Test]
    public void Exception_CanBeCaught()
    {
        // Arrange
        bool caught = false;

        // Act
        try
        {
            throw new CoseX509FormatException("Test");
        }
        catch (CoseX509FormatException)
        {
            caught = true;
        }

        // Assert
        Assert.That(caught, Is.True);
    }
}
