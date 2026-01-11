// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Tests;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.Cose;

// Register test providers for DefaultComponentDiscovery tests
// These must be at assembly level to be discovered
[assembly: DefaultValidationComponentProvider(typeof(TestSigningKeyResolverProvider))]
[assembly: DefaultValidationComponentProvider(typeof(TestHigherPriorityProvider))]

namespace CoseSign1.Validation.Tests;

/// <summary>
/// A test provider that supplies a signing key resolver for auto-discovery testing.
/// </summary>
public class TestSigningKeyResolverProvider : IDefaultValidationComponentProvider
{
    /// <summary>
    /// Lower priority so this gets processed first.
    /// </summary>
    public int Priority => 50;

    /// <summary>
    /// Returns a test signing key resolver.
    /// </summary>
    public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        yield return new TestSigningKeyResolver();
    }
}

/// <summary>
/// A test provider with higher priority number (lower priority order).
/// </summary>
public class TestHigherPriorityProvider : IDefaultValidationComponentProvider
{
    /// <summary>
    /// Higher priority number = processed later.
    /// </summary>
    public int Priority => 200;

    /// <summary>
    /// Returns a test post-signature validator.
    /// </summary>
    public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        yield return new TestPostSignatureValidator();
    }
}

/// <summary>
/// A minimal test signing key resolver implementation.
/// </summary>
public class TestSigningKeyResolver : ISigningKeyResolver
{
    public string ComponentName => "TestSigningKeyResolver";

    public bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options) => true;

    public SigningKeyResolutionResult Resolve(CoseSign1Message message)
    {
        return SigningKeyResolutionResult.Failure("Test resolver - not actually resolving keys");
    }

    public Task<SigningKeyResolutionResult> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(SigningKeyResolutionResult.Failure("Test resolver - not actually resolving keys"));
    }
}

/// <summary>
/// A minimal test post-signature validator implementation.
/// </summary>
public class TestPostSignatureValidator : IPostSignatureValidator
{
    public string ComponentName => "TestPostSignatureValidator";

    public bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options) => true;

    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        return ValidationResult.Success(ComponentName);
    }

    public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ValidationResult.Success(ComponentName));
    }
}
