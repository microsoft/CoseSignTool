// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class ValidationResultTests
{
    [Test]
    public void Success_WithValidatorName_CreatesSuccessResult()
    {
        var result = ValidationResult.Success("TestValidator");

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo("TestValidator"));
        Assert.That(result.Failures, Is.Empty);
        Assert.That(result.Metadata, Is.Empty);
    }

    [Test]
    public void Success_WithMetadata_IncludesMetadata()
    {
        var metadata = new Dictionary<string, object> { ["Key"] = "Value" };
        var result = ValidationResult.Success("TestValidator", metadata);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["Key"], Is.EqualTo("Value"));
    }

    [Test]
    public void Failure_WithSingleError_CreatesFailureResult()
    {
        var result = ValidationResult.Failure("TestValidator", "Error message", "ERROR_CODE");

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo("TestValidator"));
        Assert.That(result.Failures.Count, Is.EqualTo(1));
        Assert.That(result.Failures[0].Message, Is.EqualTo("Error message"));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("ERROR_CODE"));
    }

    [Test]
    public void Failure_WithMultipleFailures_CreatesFailureResult()
    {
        var failures = new[]
        {
            new ValidationFailure { Message = "Error 1", ErrorCode = "ERR1" },
            new ValidationFailure { Message = "Error 2", ErrorCode = "ERR2" }
        };
        var result = ValidationResult.Failure("TestValidator", failures);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(2));
        Assert.That(result.Failures[0].Message, Is.EqualTo("Error 1"));
        Assert.That(result.Failures[1].Message, Is.EqualTo("Error 2"));
    }

    [Test]
    public void Failure_WithSingleFailureObject_CreatesResult()
    {
        var failure = new ValidationFailure { Message = "Test error", ErrorCode = "TEST" };
        var result = ValidationResult.Failure("TestValidator", failure);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(1));
        Assert.That(result.Failures[0].Message, Is.EqualTo("Test error"));
    }
}

[TestFixture]
public class ValidationFailureTests
{
    [Test]
    public void ValidationFailure_SetProperties_WorksCorrectly()
    {
        var exception = new Exception("Test exception");
        var failure = new ValidationFailure
        {
            Message = "Test message",
            ErrorCode = "TEST_CODE",
            Exception = exception
        };

        Assert.That(failure.Message, Is.EqualTo("Test message"));
        Assert.That(failure.ErrorCode, Is.EqualTo("TEST_CODE"));
        Assert.That(failure.Exception, Is.EqualTo(exception));
    }

    [Test]
    public void ValidationFailure_DefaultValues_AreCorrect()
    {
        var failure = new ValidationFailure();

        Assert.That(failure.Message, Is.EqualTo(string.Empty));
        Assert.That(failure.ErrorCode, Is.Null);
        Assert.That(failure.Exception, Is.Null);
    }

    [Test]
    public void ValidationFailure_SetPropertyName_WorksCorrectly()
    {
        var failure = new ValidationFailure
        {
            Message = "Property validation failed",
            PropertyName = "UserName"
        };

        Assert.That(failure.PropertyName, Is.EqualTo("UserName"));
    }

    [Test]
    public void ValidationFailure_PropertyNameDefault_IsNull()
    {
        var failure = new ValidationFailure();

        Assert.That(failure.PropertyName, Is.Null);
    }

    [Test]
    public void ValidationFailure_SetAttemptedValue_WorksCorrectly()
    {
        var attemptedValue = "test@example.com";
        var failure = new ValidationFailure
        {
            Message = "Invalid email",
            AttemptedValue = attemptedValue
        };

        Assert.That(failure.AttemptedValue, Is.EqualTo(attemptedValue));
    }

    [Test]
    public void ValidationFailure_AttemptedValueDefault_IsNull()
    {
        var failure = new ValidationFailure();

        Assert.That(failure.AttemptedValue, Is.Null);
    }

    [Test]
    public void ValidationFailure_SetAllProperties_WorksCorrectly()
    {
        var exception = new InvalidOperationException("Operation failed");
        var attemptedValue = 42;
        var failure = new ValidationFailure
        {
            Message = "Complete failure",
            ErrorCode = "COMPLETE_FAILURE",
            PropertyName = "Age",
            AttemptedValue = attemptedValue,
            Exception = exception
        };

        Assert.That(failure.Message, Is.EqualTo("Complete failure"));
        Assert.That(failure.ErrorCode, Is.EqualTo("COMPLETE_FAILURE"));
        Assert.That(failure.PropertyName, Is.EqualTo("Age"));
        Assert.That(failure.AttemptedValue, Is.EqualTo(attemptedValue));
        Assert.That(failure.Exception, Is.EqualTo(exception));
    }

    [Test]
    public void ValidationFailure_SetAttemptedValueWithComplexObject_WorksCorrectly()
    {
        var complexObject = new { Id = 1, Name = "Test" };
        var failure = new ValidationFailure
        {
            Message = "Complex object validation failed",
            AttemptedValue = complexObject
        };

        Assert.That(failure.AttemptedValue, Is.EqualTo(complexObject));
    }

    [Test]
    public void ValidationFailure_SetAttemptedValueWithNull_WorksCorrectly()
    {
        var failure = new ValidationFailure
        {
            Message = "Null value validation",
            AttemptedValue = null
        };

        Assert.That(failure.AttemptedValue, Is.Null);
    }

    [Test]
    public void ValidationFailure_SetMessageOnly_OtherPropertiesAreDefault()
    {
        var failure = new ValidationFailure
        {
            Message = "Simple message"
        };

        Assert.That(failure.Message, Is.EqualTo("Simple message"));
        Assert.That(failure.ErrorCode, Is.Null);
        Assert.That(failure.PropertyName, Is.Null);
        Assert.That(failure.AttemptedValue, Is.Null);
        Assert.That(failure.Exception, Is.Null);
    }

    [Test]
    public void ValidationFailure_SetErrorCodeOnly_OtherPropertiesAreDefault()
    {
        var failure = new ValidationFailure
        {
            ErrorCode = "ERROR_CODE"
        };

        Assert.That(failure.Message, Is.EqualTo(string.Empty));
        Assert.That(failure.ErrorCode, Is.EqualTo("ERROR_CODE"));
        Assert.That(failure.PropertyName, Is.Null);
        Assert.That(failure.AttemptedValue, Is.Null);
        Assert.That(failure.Exception, Is.Null);
    }

    [Test]
    public void ValidationFailure_SetExceptionWithInnerException_WorksCorrectly()
    {
        var innerException = new ArgumentException("Inner error");
        var exception = new InvalidOperationException("Outer error", innerException);
        var failure = new ValidationFailure
        {
            Message = "Exception with inner",
            Exception = exception
        };

        Assert.That(failure.Exception, Is.EqualTo(exception));
        Assert.That(failure.Exception!.InnerException, Is.EqualTo(innerException));
    }

    [Test]
    public void ValidationFailure_SetPropertyNameWithEmptyString_WorksCorrectly()
    {
        var failure = new ValidationFailure
        {
            PropertyName = ""
        };

        Assert.That(failure.PropertyName, Is.EqualTo(""));
    }

    [Test]
    public void ValidationFailure_SetAttemptedValueWithZero_WorksCorrectly()
    {
        var failure = new ValidationFailure
        {
            Message = "Zero value validation",
            AttemptedValue = 0
        };

        Assert.That(failure.AttemptedValue, Is.EqualTo(0));
    }

    [Test]
    public void ValidationFailure_SetAttemptedValueWithFalse_WorksCorrectly()
    {
        var failure = new ValidationFailure
        {
            Message = "Boolean validation",
            AttemptedValue = false
        };

        Assert.That(failure.AttemptedValue, Is.EqualTo(false));
    }

    [Test]
    public void ValidationFailure_SetAttemptedValueWithEmptyString_WorksCorrectly()
    {
        var failure = new ValidationFailure
        {
            Message = "Empty string validation",
            AttemptedValue = ""
        };

        Assert.That(failure.AttemptedValue, Is.EqualTo(""));
    }
}
