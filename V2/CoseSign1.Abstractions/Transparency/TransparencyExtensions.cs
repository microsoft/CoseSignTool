// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="provider"/> is <see langword="null"/>.</exception>
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
        Cose.Abstractions.Guard.ThrowIfNull(message);
        Cose.Abstractions.Guard.ThrowIfNull(provider);

        return provider.VerifyTransparencyProofAsync(message, cancellationToken);
    }

    /// <summary>
    /// Verifies transparency proofs in a COSE Sign1 message using multiple providers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="providers">The transparency providers to use for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A collection of validation results, one per provider.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="providers"/> is <see langword="null"/>.</exception>
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
        Cose.Abstractions.Guard.ThrowIfNull(message);
        Cose.Abstractions.Guard.ThrowIfNull(providers);

        var results = new List<TransparencyValidationResult>(providers.Count);

        foreach (var provider in providers)
        {
            var result = await provider.VerifyTransparencyProofAsync(message, cancellationToken).ConfigureAwait(false);
            results.Add(result);
        }

        return results;
    }

    /// <summary>
    /// Attempts to extract receipts from the transparency header (label 394) of a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract receipts from.</param>
    /// <param name="receipts">When this method returns, contains the list of receipt byte arrays if found; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if receipts were successfully extracted; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is <see langword="null"/>.</exception>
    public static bool TryGetReceipts(this CoseSign1Message message, out List<byte[]>? receipts)
    {
        Guard.ThrowIfNull(message);

        return TransparencyProviderBase.TryGetReceipts(message, out receipts);
    }

    /// <summary>
    /// Adds receipts to the transparency header (label 394) of a <see cref="CoseSign1Message"/>,
    /// merging with any existing receipts and de-duplicating by byte content.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to add receipts to.</param>
    /// <param name="receipts">The list of receipt byte arrays to add.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="receipts"/> is <see langword="null"/>.</exception>
    public static void AddReceipts(this CoseSign1Message message, List<byte[]> receipts)
    {
        Guard.ThrowIfNull(message);
        Guard.ThrowIfNull(receipts);

        TransparencyProviderBase.MergeReceipts(message, receipts);
    }

    /// <summary>
    /// Verifies the transparency proof in a COSE Sign1 message using a specific receipt
    /// and the specified <see cref="TransparencyProviderBase"/>.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="provider">The transparency provider to use for verification.</param>
    /// <param name="receipt">The receipt to embed and verify against.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="receipt"/> is empty.</exception>
    public static Task<TransparencyValidationResult> VerifyTransparencyAsync(
        this CoseSign1Message message,
        TransparencyProviderBase provider,
        byte[] receipt,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);
        Guard.ThrowIfNull(provider);
        Guard.ThrowIfNull(receipt);

        return provider.VerifyTransparencyProofAsync(message, receipt, cancellationToken);
    }
}