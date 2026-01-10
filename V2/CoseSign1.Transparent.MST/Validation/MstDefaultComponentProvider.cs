// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides default MST (Microsoft Signing Transparency) validation components for auto-discovery.
/// </summary>
/// <remarks>
/// <para>
/// This provider supplies MST receipt presence validation:
/// <list type="bullet">
/// <item><description><see cref="MstReceiptPresenceAssertionProvider"/> - Emits assertions about MST receipt presence</description></item>
/// </list>
/// </para>
/// <para>
/// Note: This provider only checks for receipt <em>presence</em>, not validity.
/// For full receipt verification, use the builder pattern to add <see cref="MstReceiptAssertionProvider"/>
/// with an appropriate <see cref="MstTransparencyProvider"/>.
/// </para>
/// </remarks>
public sealed class MstDefaultComponentProvider : IDefaultValidationComponentProvider
{
    /// <inheritdoc/>
    /// <remarks>
    /// Priority 200 places MST components in the trust/transparency tier,
    /// after core certificate validation.
    /// </remarks>
    public int Priority => 200;

    /// <inheritdoc/>
    public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        // MST receipt presence check - emits assertions about whether receipts exist
        // Note: Does NOT verify receipts - that requires explicit configuration with MstTransparencyProvider
        yield return new MstReceiptPresenceAssertionProvider();
    }
}
