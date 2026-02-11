// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Tests;

using CoseSign1.Factories.Exceptions;

[TestFixture]
public class SignatureVerificationExceptionTests
{
    [Test]
    public void DefaultConstructor_SetsDefaultMessage()
    {
        SignatureVerificationException ex = new();

        Assert.That(ex.Message, Is.Not.Null.And.Not.Empty);
        Assert.That(ex.OperationId, Is.Null);
    }

    [Test]
    public void MessageConstructor_SetsMessage()
    {
        SignatureVerificationException ex = new("custom error");

        Assert.That(ex.Message, Is.EqualTo("custom error"));
        Assert.That(ex.OperationId, Is.Null);
    }

    [Test]
    public void MessageAndInnerExceptionConstructor_SetsMessageAndInnerException()
    {
        Exception inner = new InvalidOperationException("inner");
        SignatureVerificationException ex = new("outer error", inner);

        Assert.That(ex.Message, Is.EqualTo("outer error"));
        Assert.That(ex.InnerException, Is.SameAs(inner));
    }

    [Test]
    public void MessageAndOperationIdConstructor_SetsOperationId()
    {
        SignatureVerificationException ex = new("error", "op-123");

        Assert.That(ex.Message, Is.EqualTo("error"));
        Assert.That(ex.OperationId, Is.EqualTo("op-123"));
    }

    [Test]
    public void MessageAndNullOperationId_SetsNullOperationId()
    {
        SignatureVerificationException ex = new("error", operationId: null);

        Assert.That(ex.OperationId, Is.Null);
    }
}