// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

/// <summary>
/// Marker interface for all validation pipeline components.
/// </summary>
/// <remarks>
/// <para>
/// Components are passed to the validator orchestrator as a single list.
/// The orchestrator filters components by their specific interface type
/// and invokes them at the appropriate stage:
/// </para>
/// <list type="number">
/// <item><description><see cref="ISigningKeyResolver"/> - Key material resolution</description></item>
/// <item><description><see cref="ISigningKeyAssertionProvider"/> - Trust assertion extraction</description></item>
/// <item><description>Signature Verification - Performed directly using the resolved signing key</description></item>
/// <item><description><see cref="IPostSignatureValidator"/> - Post-signature policy checks</description></item>
/// </list>
/// <para>
/// A component may implement multiple interfaces if it participates in multiple stages.
/// </para>
/// </remarks>
public interface IValidationComponent
{
    /// <summary>
    /// Gets a unique name identifying this component for logging and diagnostics.
    /// </summary>
    string ComponentName { get; }
}
