// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Transparent.Extensions;

/// <summary>
/// Base class for transparency services that ensures receipts are preserved when a service returns a new
/// <see cref="CoseSign1Message"/> instance.
/// </summary>
public abstract class TransparencyService
{
    protected TransparencyService()
        : this(null, null, null)
    {
    }

    protected TransparencyService(Action<string>? logVerbose = null, Action<string>? logWarning = null, Action<string>? logError = null)
    {
        LogVerbose = logVerbose;
        LogWarning = logWarning;
        LogError = logError;
    }

    protected Action<string>? LogVerbose { get; }
    protected Action<string>? LogWarning { get; }
    protected Action<string>? LogError { get; }

    /// <summary>
    /// Creates a new transparent COSE Sign1 message by embedding additional metadata or headers into the provided message.
    /// </summary>
    public virtual async Task<CoseSign1Message> MakeTransparentAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        string serviceName = GetType().Name;
        Stopwatch stopwatch = Stopwatch.StartNew();

        int inputReceiptCount = 0;
        _ = message.TryGetReceipts(out List<byte[]>? existingReceipts);
        inputReceiptCount = existingReceipts?.Count ?? 0;

        LogVerbose?.Invoke($"[{serviceName}] MakeTransparentAsync starting. Input receipts: {inputReceiptCount}.");

        CoseSign1Message result;
        try
        {
            result = await MakeTransparentCoreAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogError?.Invoke($"[{serviceName}] MakeTransparentAsync failed after {stopwatch.ElapsedMilliseconds}ms: {ex.Message}");
            throw;
        }

        if (result == null)
        {
            throw new InvalidOperationException($"[{serviceName}] MakeTransparentCoreAsync returned null.");
        }

        _ = result.TryGetReceipts(out List<byte[]>? resultReceiptsBeforeMerge);
        int resultReceiptCountBeforeMerge = resultReceiptsBeforeMerge?.Count ?? 0;

        if (existingReceipts is { Count: > 0 })
        {
            result.AddReceipts(existingReceipts);
        }

        _ = result.TryGetReceipts(out List<byte[]>? resultReceiptsAfterMerge);
        int resultReceiptCountAfterMerge = resultReceiptsAfterMerge?.Count ?? 0;

        LogVerbose?.Invoke(
            $"[{serviceName}] MakeTransparentAsync completed in {stopwatch.ElapsedMilliseconds}ms. " +
            $"Result receipts: {resultReceiptCountBeforeMerge} -> {resultReceiptCountAfterMerge}.");

        return result;
    }

    /// <summary>
    /// Implemented by derived services to perform the actual transparency operation.
    /// The returned message may be a new instance.
    /// </summary>
    protected virtual Task<CoseSign1Message> MakeTransparentCoreAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Derived classes must override MakeTransparentCoreAsync or override MakeTransparentAsync.");

    /// <summary>
    /// Verifies the transparency of the message.
    /// </summary>
    public virtual Task<bool> VerifyTransparencyAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        return VerifyTransparencyCoreAsync(message, cancellationToken);
    }

    /// <summary>
    /// Verifies the transparency of the message using a specific receipt.
    /// </summary>
    public virtual Task<bool> VerifyTransparencyAsync(CoseSign1Message message, byte[] receipt, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        if (receipt == null)
        {
            throw new ArgumentNullException(nameof(receipt));
        }

        return VerifyTransparencyWithReceiptCoreAsync(message, receipt, cancellationToken);
    }

    /// <summary>
    /// Implemented by derived services to verify transparency.
    /// </summary>
    protected virtual Task<bool> VerifyTransparencyCoreAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Derived classes must override VerifyTransparencyCoreAsync or override VerifyTransparencyAsync.");

    /// <summary>
    /// Implemented by derived services to verify transparency using a receipt.
    /// </summary>
    protected virtual Task<bool> VerifyTransparencyWithReceiptCoreAsync(CoseSign1Message message, byte[] receipt, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Derived classes must override VerifyTransparencyWithReceiptCoreAsync or override VerifyTransparencyAsync.");
}
