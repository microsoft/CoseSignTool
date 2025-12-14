// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Validates that a COSE Sign1 message contains an MST transparency receipt.
/// </summary>
public sealed class MstReceiptPresenceValidator : IValidator<CoseSign1Message>
{
    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(MstReceiptPresenceValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        // Check if the message has an MST receipt
        if (!input.HasMstReceipt())
        {
            return ValidationResult.Failure(
                nameof(MstReceiptPresenceValidator),
                "Message does not contain an MST transparency receipt",
                "MST_RECEIPT_NOT_FOUND");
        }

        // Try to extract the receipts
        var receipts = input.GetMstReceipts();
        if (receipts.Count == 0)
        {
            return ValidationResult.Failure(
                nameof(MstReceiptPresenceValidator),
                "Failed to extract MST receipt from message",
                "MST_RECEIPT_EXTRACTION_FAILED");
        }

        return ValidationResult.Success(nameof(MstReceiptPresenceValidator), new Dictionary<string, object>
        {
            ["ReceiptCount"] = receipts.Count,
            ["ReceiptSizes"] = receipts.Select(r => r.Encode().Length).ToArray()
        });
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}