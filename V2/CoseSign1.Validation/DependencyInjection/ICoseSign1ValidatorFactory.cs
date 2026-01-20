// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.DependencyInjection;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>
/// Factory for creating fully-wired <see cref="ICoseSign1Validator"/> instances from a DI container.
/// </summary>
/// <remarks>
/// <para>
/// This is a convenience for DI-based applications. It avoids requiring callers to manually pass
/// <see cref="ISigningKeyResolver"/> and <see cref="IPostSignatureValidator"/> collections and to compile
/// a <see cref="CompiledTrustPlan"/>.
/// </para>
/// <para>
/// Non-DI callers can continue to use <see cref="CoseSign1Validator"/>'s constructor and pass explicit components.
/// </para>
/// </remarks>
public interface ICoseSign1ValidatorFactory
{
    /// <summary>
    /// Creates a validator using services registered in the current container/scope.
    /// </summary>
    /// <param name="options">Optional validation options (detached payload, associated data, signature-only mode).</param>
    /// <param name="trustEvaluationOptions">Optional trust evaluation options (including bypass).</param>
    /// <param name="trustPlanKey">
    /// Optional key used to resolve a pre-compiled <see cref="CompiledTrustPlan"/> from the DI container.
    /// If provided, the keyed registration must exist and be non-null.
    /// If not provided, the factory will prefer an unkeyed <see cref="CompiledTrustPlan"/> registration when present,
    /// otherwise it will compute defaults via <see cref="CompiledTrustPlan.CompileDefaults(IServiceProvider)"/>.
    /// </param>
    /// <param name="logger">Optional logger. If null, resolves <see cref="ILogger{TCategoryName}"/> from the container when available.</param>
    /// <returns>A configured validator instance.</returns>
    ICoseSign1Validator Create(
        CoseSign1ValidationOptions? options = null,
        TrustEvaluationOptions? trustEvaluationOptions = null,
        string? trustPlanKey = null,
        ILogger<CoseSign1Validator>? logger = null);
}

internal sealed class CoseSign1ValidatorFactory : ICoseSign1ValidatorFactory
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorNoKeyedTrustPlan = "No keyed CompiledTrustPlan registration was found for key '{0}'.";
    }

    private readonly IServiceProvider Services;

    public CoseSign1ValidatorFactory(IServiceProvider services)
    {
        Guard.ThrowIfNull(services);
        Services = services;
    }

    public ICoseSign1Validator Create(
        CoseSign1ValidationOptions? options = null,
        TrustEvaluationOptions? trustEvaluationOptions = null,
        string? trustPlanKey = null,
        ILogger<CoseSign1Validator>? logger = null)
    {
        var signingKeyResolvers = Services.GetServices<ISigningKeyResolver>().ToList();
        var postSignatureValidators = Services.GetServices<IPostSignatureValidator>();
        var toBeSignedAttestors = Services.GetServices<IToBeSignedAttestor>();

        // Trust packs may provide a tightly-coupled signing key resolver.
        foreach (var pack in Services.GetServices<ITrustPack>())
        {
            if (pack.SigningKeyResolver != null)
            {
                signingKeyResolvers.Add(pack.SigningKeyResolver);
            }
        }

        CompiledTrustPlan trustPlan;
        if (!string.IsNullOrWhiteSpace(trustPlanKey))
        {
            trustPlan = Services.GetKeyedService<CompiledTrustPlan>(trustPlanKey)
                ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorNoKeyedTrustPlan, trustPlanKey));
        }
        else
        {
            trustPlan = Services.GetService<CompiledTrustPlan>()
                ?? CompiledTrustPlan.CompileDefaults(Services);
        }

        var resolvedLogger = logger ?? Services.GetService<ILogger<CoseSign1Validator>>();

        return new CoseSign1Validator(
            signingKeyResolvers,
            postSignatureValidators,
            toBeSignedAttestors,
            trustPlan,
            options,
            trustEvaluationOptions,
            resolvedLogger);
    }
}
