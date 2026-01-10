// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Abstractions;

/// <summary>
/// Abstract base class for MST (Microsoft Signing Transparency) validation components.
/// </summary>
/// <remarks>
/// <para>
/// Extends <see cref="ValidationComponentBase"/> with MST-specific helpers.
/// Provides a default implementation of <see cref="ComputeApplicability"/> that optionally
/// checks for the presence of MST receipts in the message.
/// </para>
/// <para>
/// Derived classes can override <see cref="ComputeApplicability"/> to add additional
/// applicability checks while still leveraging the base MST check via
/// <see cref="HasMstReceipt"/>.
/// </para>
/// </remarks>
public abstract class MstValidationComponentBase : ValidationComponentBase
{
    /// <summary>
    /// Gets a value indicating whether this component requires MST receipts to be present.
    /// </summary>
    /// <remarks>
    /// When <c>true</c>, <see cref="ComputeApplicability"/> returns <c>false</c> for messages without MST receipts.
    /// When <c>false</c>, this component is applicable to any non-null message and will emit
    /// appropriate assertions (e.g., ReceiptPresent=false) when no receipt is found.
    /// Default is <c>false</c> to allow assertion providers to emit "no receipt" facts.
    /// </remarks>
    protected virtual bool RequireMstReceipt => false;

    /// <inheritdoc/>
    /// <remarks>
    /// Default implementation checks for non-null message, optionally requiring MST receipt presence.
    /// Override to add additional applicability checks.
    /// </remarks>
    protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
    {
        if (RequireMstReceipt)
        {
            return HasMstReceipt(message);
        }

        // By default, MST components are applicable to any message
        // They will emit appropriate assertions based on receipt presence
        return true;
    }

    /// <summary>
    /// Checks if the message has an MST receipt in its headers.
    /// </summary>
    /// <param name="message">The message to check.</param>
    /// <returns><c>true</c> if the message has an MST receipt.</returns>
    protected static bool HasMstReceipt(CoseSign1Message? message)
    {
        return message?.HasMstReceipt() == true;
    }
}
