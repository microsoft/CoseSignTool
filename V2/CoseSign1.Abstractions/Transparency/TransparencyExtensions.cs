// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;

namespace CoseSign1.Abstractions.Transparency;

/// <summary>
/// Extension methods for working with transparent COSE Sign1 messages.
/// </summary>
/// <remarks>
/// Provider-specific packages (e.g., CoseSign1.Transparent.CTS) should add their own
/// extension methods for checking the presence of specific transparency proofs.
/// For example:
/// <code>
/// // In CoseSign1.Transparent.CTS:
/// public static bool HasCtsReceipt(this CoseSign1Message message)
/// {
///     return message.UnprotectedHeaders?.TryGetValue(CtsHeaderLabel, out _) == true;
/// }
/// </code>
/// </remarks>
public static class TransparencyExtensions
{
    /// <summary>
    /// Verifies the transparency proof in a COSE Sign1 message using the specified provider.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="provider">The transparency provider to use for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <example>
    /// <code>
    /// var ctsProvider = new AzureCtsTransparencyProvider(client);
    /// var result = await message.VerifyTransparencyAsync(ctsProvider);
    /// 
    /// if (result.IsValid)
    /// {
    ///     Console.WriteLine($"Valid {result.ProviderName} proof");
    /// }
    /// </code>
    /// </example>
    public static Task<TransparencyValidationResult> VerifyTransparencyAsync(
        this CoseSign1Message message,
        ITransparencyProvider provider,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (provider == null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        return provider.VerifyTransparencyProofAsync(message, cancellationToken);
    }

    /// <summary>
    /// Verifies transparency proofs in a COSE Sign1 message using multiple providers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="providers">The transparency providers to use for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A collection of validation results, one per provider.</returns>
    /// <example>
    /// <code>
    /// var providers = new ITransparencyProvider[]
    /// {
    ///     new AzureCtsTransparencyProvider(ctsClient),
    ///     new CertificateTransparencyProvider(sctClient)
    /// };
    /// 
    /// var results = await message.VerifyTransparencyAsync(providers);
    /// 
    /// foreach (var result in results)
    /// {
    ///     Console.WriteLine($"{result.ProviderName}: {(result.IsValid ? "Valid" : "Invalid")}");
    /// }
    /// </code>
    /// </example>
    public static async Task<IReadOnlyList<TransparencyValidationResult>> VerifyTransparencyAsync(
        this CoseSign1Message message,
        IReadOnlyList<ITransparencyProvider> providers,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (providers == null)
        {
            throw new ArgumentNullException(nameof(providers));
        }

        var results = new List<TransparencyValidationResult>(providers.Count);
        
        foreach (var provider in providers)
        {
            var result = await provider.VerifyTransparencyProofAsync(message, cancellationToken).ConfigureAwait(false);
            results.Add(result);
        }

        return results;
    }
}
