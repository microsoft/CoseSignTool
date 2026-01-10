// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Builder for constructing a staged COSE Sign1 validation pipeline.
/// </summary>
/// <remarks>
/// <para>
/// Use <c>new CoseSign1ValidationBuilder()</c> to create a builder, configure it with
/// extension methods, and call <see cref="Build"/> to create a reusable validator.
/// </para>
/// <para>
/// For one-off validation, use the <see cref="System.Security.Cryptography.Cose.CoseSign1Message"/> extension methods
/// like <c>message.Validate(builder => ...)</c> instead.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// var validator = new CoseSign1ValidationBuilder()
///     .ValidateCertificate(cert => cert.ValidateChain())
///     .Build();
/// 
/// var result = message.Validate(validator);
/// </code>
/// </example>
public sealed class CoseSign1ValidationBuilder : ICoseSign1ValidationBuilder
{
    internal static class ClassStrings
    {
        public const string ErrorValidationRequiresSigningKeyResolver = "Validation requires at least one signing key resolver (ISigningKeyResolver).";
    }

    private readonly List<IValidationComponent> Components = new();

    private TrustPolicy? ExplicitTrustPolicy;

    private bool SkipContentVerification;

    private CoseSign1ValidationOptions ValidationOptions = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1ValidationBuilder"/> class.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in validators.</param>
    public CoseSign1ValidationBuilder(ILoggerFactory? loggerFactory = null)
    {
        LoggerFactory = loggerFactory;
    }

    /// <inheritdoc/>
    public ILoggerFactory? LoggerFactory { get; }

    /// <summary>
    /// Adds a validation component to the builder.
    /// </summary>
    /// <param name="component">The component to add.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="component"/> is null.</exception>
    public ICoseSign1ValidationBuilder AddComponent(IValidationComponent component)
    {
        if (component == null)
        {
            throw new ArgumentNullException(nameof(component));
        }

        Components.Add(component);
        return this;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public ICoseSign1ValidationBuilder WithOptions(CoseSign1ValidationOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        ValidationOptions = options;
        return this;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    public ICoseSign1ValidationBuilder WithOptions(Action<CoseSign1ValidationOptions> configure)
    {
        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        configure(ValidationOptions);
        return this;
    }

    /// <summary>
    /// Overrides the default trust policy with a custom policy.
    /// </summary>
    /// <param name="policy">The trust policy to use.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policy"/> is null.</exception>
    public ICoseSign1ValidationBuilder OverrideDefaultTrustPolicy(TrustPolicy policy)
    {
        if (policy == null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        ExplicitTrustPolicy = policy;
        return this;
    }

    /// <summary>
    /// Sets trust policy to allow all.
    /// </summary>
    /// <param name="reason">Optional reason describing why all trust is allowed.</param>
    /// <returns>The same builder instance.</returns>
    public ICoseSign1ValidationBuilder AllowAllTrust(string? reason = null)
    {
        ExplicitTrustPolicy = TrustPolicy.AllowAll(reason);
        return this;
    }

    /// <summary>
    /// Sets trust policy to deny all.
    /// </summary>
    /// <param name="reason">Optional reason describing why all trust is denied.</param>
    /// <returns>The same builder instance.</returns>
    public ICoseSign1ValidationBuilder DenyAllTrust(string? reason = null)
    {
        ExplicitTrustPolicy = TrustPolicy.DenyAll(reason);
        return this;
    }

    /// <summary>
    /// Disables automatic indirect signature validation.
    /// </summary>
    /// <remarks>
    /// By default, <see cref="PostSignature.IndirectSignatureValidator"/> is automatically added to validate
    /// payload hashes for indirect signatures. Call this method to disable that behavior.
    /// </remarks>
    /// <returns>The same builder instance.</returns>
    public ICoseSign1ValidationBuilder WithoutContentVerification()
    {
        SkipContentVerification = true;
        return this;
    }

    /// <summary>
    /// Builds a reusable validator instance.
    /// </summary>
    /// <returns>A validator instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the builder does not include a signing key resolver.</exception>
    public ICoseSign1Validator Build()
    {
        var signingKeyResolvers = Components.OfType<ISigningKeyResolver>().ToList();
        if (signingKeyResolvers.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorValidationRequiresSigningKeyResolver);
        }

        // Use explicit trust policy if provided, otherwise use assertion defaults
        var trustPolicy = ExplicitTrustPolicy ?? TrustPolicy.FromAssertionDefaults();

        // Build final component list, adding default validators unless skipped
        var finalComponents = new List<IValidationComponent>(Components);

        if (!SkipContentVerification)
        {
            var logger = LoggerFactory?.CreateLogger<PostSignature.IndirectSignatureValidator>();
            finalComponents.Add(new PostSignature.IndirectSignatureValidator(logger));
        }

        return new CoseSign1Validator(finalComponents.ToArray(), trustPolicy, ValidationOptions);
    }
}
