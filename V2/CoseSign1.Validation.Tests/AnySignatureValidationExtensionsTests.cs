// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class AnySignatureValidationExtensionsTests
{
    [Test]
    public void AddAnySignatureValidator_WithNullBuilder_ThrowsArgumentNullException()
    {
        CoseMessageValidationBuilder? builder = null;

        var ex = Assert.Throws<ArgumentNullException>(() =>
            builder!.AddAnySignatureValidator(_ => { }));

        Assert.That(ex!.ParamName, Is.EqualTo("builder"));
    }

    [Test]
    public void AddAnySignatureValidator_WithNullConfigure_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();

        var ex = Assert.Throws<ArgumentNullException>(() =>
            builder.AddAnySignatureValidator(null!));

        Assert.That(ex!.ParamName, Is.EqualTo("configure"));
    }

    [Test]
    public void AddAnySignatureValidator_WithNoCandidates_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<InvalidOperationException>(() =>
            builder.AddAnySignatureValidator(_ => { }));
    }

    [Test]
    public void AddAnySignatureValidator_WithCandidate_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.AddAnySignatureValidator(b => b.Add(new AlwaysPassValidator()));

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AddAnySignatureValidator_WithNullCandidateValidator_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();

        var ex = Assert.Throws<ArgumentNullException>(() =>
            builder.AddAnySignatureValidator(b => b.Add(null!)));

        Assert.That(ex!.ParamName, Is.EqualTo("validator"));
    }

    private sealed class AlwaysPassValidator : IValidator<CoseSign1Message>
    {
        public ValidationResult Validate(CoseSign1Message input) => ValidationResult.Success(nameof(AlwaysPassValidator));

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input));
    }
}
