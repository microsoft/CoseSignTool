// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Transparency;

using System.Collections;
using System.Diagnostics;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Abstract base class for transparency providers that ensures receipts are preserved when a provider
/// returns a new <see cref="CoseSign1Message"/> instance.
/// </summary>
/// <remarks>
/// Many transparency services (e.g., Azure CTS) return a completely new <see cref="CoseSign1Message"/>
/// from their registration endpoint. This new message may not contain receipts from other transparency
/// providers that were previously applied. This base class captures existing receipts before delegating
/// to the derived implementation, then merges them back into the result.
///
/// Derived classes should override <see cref="AddTransparencyProofCoreAsync"/> and
/// <see cref="VerifyTransparencyProofCoreAsync"/> instead of the public methods.
/// </remarks>
public abstract class TransparencyProviderBase : ITransparencyProvider
{
    /// <summary>
    /// The header label used to indicate transparency in COSE Sign1 messages in SCITT.
    /// </summary>
    /// <remarks>
    /// The label value 394 was a previously proposed identifier for transparency in COSE Sign1 messages.
    /// However, it is not yet finalized in the IANA registry. The SCITT draft now uses a placeholder
    /// value (TBD_0) for this label.
    /// </remarks>
    protected static readonly CoseHeaderLabel TransparencyHeaderLabel = new(394);

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string LogMakeTransparentStartFormat = "[{0}] AddTransparencyProofAsync starting. Input receipts: {1}.";
        public const string LogMakeTransparentCompleteFormat = "[{0}] AddTransparencyProofAsync completed in {1}ms. Result receipts: {2} -> {3}.";
        public const string LogMakeTransparentFailedFormat = "[{0}] AddTransparencyProofAsync failed after {1}ms: {2}";
        public const string ErrorNullResult = "AddTransparencyProofCoreAsync returned null.";
        public const string ErrorReceiptsEmpty = "Receipts cannot be empty.";
        public const string ErrorNullResultFormat = "[{0}] AddTransparencyProofCoreAsync returned null.";
        public const string ErrorNotImplemented = "Derived classes must override VerifyTransparencyProofCoreAsync or override VerifyTransparencyProofAsync.";
        public const string ErrorInvalidCborFormat = "Invalid CBOR format for receipts, they must be an array.";
    }

    /// <summary>
    /// Optional verbose logging callback.
    /// </summary>
    protected Action<string>? LogVerbose { get; }

    /// <summary>
    /// Optional error logging callback.
    /// </summary>
    protected Action<string>? LogError { get; }

    /// <inheritdoc/>
    public abstract string ProviderName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TransparencyProviderBase"/> class.
    /// </summary>
    protected TransparencyProviderBase()
        : this(null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TransparencyProviderBase"/> class with logging callbacks.
    /// </summary>
    /// <param name="logVerbose">Optional verbose logging callback.</param>
    /// <param name="logError">Optional error logging callback.</param>
    protected TransparencyProviderBase(Action<string>? logVerbose, Action<string>? logError)
    {
        LogVerbose = logVerbose;
        LogError = logError;
    }

    /// <summary>
    /// Adds transparency proof to the signed COSE message, preserving any existing receipts
    /// from other transparency providers.
    /// </summary>
    /// <param name="message">The signed COSE Sign1 message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new message with transparency proof and all prior receipts preserved.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the derived implementation returns null.</exception>
    public async Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);

        Stopwatch stopwatch = Stopwatch.StartNew();

        // Capture existing receipts before the derived implementation potentially replaces the message
        TryGetReceipts(message, out List<byte[]>? existingReceipts);
        int inputReceiptCount = existingReceipts?.Count ?? 0;

        LogVerbose?.Invoke(string.Format(ClassStrings.LogMakeTransparentStartFormat, ProviderName, inputReceiptCount));

        CoseSign1Message result;
        try
        {
            result = await AddTransparencyProofCoreAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogError?.Invoke(string.Format(ClassStrings.LogMakeTransparentFailedFormat, ProviderName, stopwatch.ElapsedMilliseconds, ex.Message));
            throw;
        }

        if (result is null)
        {
            throw new InvalidOperationException(string.Format(ClassStrings.ErrorNullResultFormat, ProviderName));
        }

        // Count receipts on the result before merging
        TryGetReceipts(result, out List<byte[]>? resultReceiptsBeforeMerge);
        int resultReceiptCountBeforeMerge = resultReceiptsBeforeMerge?.Count ?? 0;

        // Merge original receipts back in (de-duplicated, preserving order)
        if (existingReceipts is { Count: > 0 })
        {
            MergeReceipts(result, existingReceipts);
        }

        TryGetReceipts(result, out List<byte[]>? resultReceiptsAfterMerge);
        int resultReceiptCountAfterMerge = resultReceiptsAfterMerge?.Count ?? 0;

        LogVerbose?.Invoke(string.Format(
            ClassStrings.LogMakeTransparentCompleteFormat,
            ProviderName,
            stopwatch.ElapsedMilliseconds,
            resultReceiptCountBeforeMerge,
            resultReceiptCountAfterMerge));

        return result;
    }

    /// <summary>
    /// Implemented by derived providers to perform the actual transparency proof addition.
    /// The returned message may be a new instance; the base class will ensure receipts are preserved.
    /// </summary>
    /// <param name="message">The signed COSE Sign1 message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new or modified message with transparency proof added.</returns>
    protected abstract Task<CoseSign1Message> AddTransparencyProofCoreAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);

    /// <inheritdoc/>
    public virtual Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);

        return VerifyTransparencyProofCoreAsync(message, cancellationToken);
    }

    /// <summary>
    /// Implemented by derived providers to verify transparency proof.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation result with status and details.</returns>
    protected virtual Task<TransparencyValidationResult> VerifyTransparencyProofCoreAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
        => throw new NotImplementedException(ClassStrings.ErrorNotImplemented);

    #region Receipt Helpers

    /// <summary>
    /// Attempts to extract receipts from the transparency header of a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract receipts from.</param>
    /// <param name="receipts">When this method returns, contains the list of receipt byte arrays if found; otherwise null.</param>
    /// <returns>True if receipts were successfully extracted; otherwise false.</returns>
    protected internal static bool TryGetReceipts(CoseSign1Message message, out List<byte[]>? receipts)
    {
        receipts = null;

        if (message?.UnprotectedHeaders?.TryGetValue(TransparencyHeaderLabel, out CoseHeaderValue receiptValue) != true)
        {
            return false;
        }

        try
        {
            receipts = ParseCoseHeaderToArray(receiptValue);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (CborContentException)
        {
            return false;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    /// <summary>
    /// Merges the provided receipts into the message's transparency header, de-duplicating by byte content.
    /// Existing receipts on the message are preserved and appear first.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to merge receipts into.</param>
    /// <param name="receipts">The receipts to merge in.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="receipts"/> is null.</exception>
    protected internal static void MergeReceipts(CoseSign1Message message, List<byte[]> receipts)
    {
        Guard.ThrowIfNull(message);
        Guard.ThrowIfNull(receipts);

        TryGetReceipts(message, out List<byte[]>? existingReceiptsList);

        // Merge and de-duplicate receipts (by byte content), preserving stable order:
        // existing receipts first, then newly provided receipts.
        List<byte[]> mergedReceipts = new();
        HashSet<byte[]> seen = new(ByteArrayComparer.Instance);

        if (existingReceiptsList != null)
        {
            foreach (byte[] receipt in existingReceiptsList)
            {
                if (receipt is null || receipt.Length == 0)
                {
                    continue;
                }

                if (seen.Add(receipt))
                {
                    mergedReceipts.Add(receipt);
                }
            }
        }

        foreach (byte[] receipt in receipts)
        {
            if (receipt is null || receipt.Length == 0)
            {
                continue;
            }

            if (seen.Add(receipt))
            {
                mergedReceipts.Add(receipt);
            }
        }

        if (mergedReceipts.Count == 0)
        {
            return;
        }

        // Write the receipts to a CBOR-encoded array
        CborWriter cborWriter = new();
        cborWriter.WriteStartArray(mergedReceipts.Count);

        foreach (byte[] receipt in mergedReceipts)
        {
            cborWriter.WriteByteString(receipt);
        }

        cborWriter.WriteEndArray();

        // Replace the existing receipts in the unprotected headers
        if (message.UnprotectedHeaders.ContainsKey(TransparencyHeaderLabel))
        {
            message.UnprotectedHeaders.Remove(TransparencyHeaderLabel);
        }

        message.UnprotectedHeaders.Add(TransparencyHeaderLabel, CoseHeaderValue.FromEncodedValue(cborWriter.Encode()));
    }

    private static List<byte[]> ParseCoseHeaderToArray(CoseHeaderValue headerValue)
    {
        List<byte[]> values = new();
        CborReader cborReader = new(headerValue.EncodedValue);

        if (cborReader.PeekState() != CborReaderState.StartArray)
        {
            throw new InvalidOperationException(ClassStrings.ErrorInvalidCborFormat);
        }

        cborReader.ReadStartArray();

        while (cborReader.PeekState() != CborReaderState.EndArray)
        {
            if (cborReader.PeekState() == CborReaderState.ByteString)
            {
                values.Add(cborReader.ReadByteString());
            }
            else
            {
                cborReader.SkipValue();
            }
        }

        return values;
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        public bool Equals(byte[]? x, byte[]? y)
            => StructuralComparisons.StructuralEqualityComparer.Equals(x, y);

        public int GetHashCode(byte[] obj)
            => StructuralComparisons.StructuralEqualityComparer.GetHashCode(obj);
    }

    #endregion
}