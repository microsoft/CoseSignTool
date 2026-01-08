// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Defines the high-level stage of a validation operation.
/// </summary>
/// <remarks>
/// <para>
/// Stages are used by orchestration layers (e.g., CLI verification) to enforce secure-by-default ordering.
/// The intended order is:
/// </para>
/// <list type="number">
/// <item><description><see cref="KeyMaterialResolution"/>: locate and decode candidate signing key material.</description></item>
/// <item><description><see cref="KeyMaterialTrust"/>: evaluate trust/identity/policy for the resolved key material.</description></item>
/// <item><description><see cref="Signature"/>: perform cryptographic signature verification.</description></item>
/// <item><description><see cref="PostSignature"/>: apply any additional policy that depends on a verified signature.</description></item>
/// </list>
/// <para>
/// IMPORTANT: The stage indicates <em>when</em> a validator should run, not whether it is applicable.
/// Applicability remains the responsibility of the validator (often via <see cref="global::CoseSign1.Validation.Interfaces.IConditionalValidator"/>).
/// </para>
/// </remarks>
public enum ValidationStage
{
    /// <summary>
    /// Locate, extract, and decode signing key material (e.g., parse headers, decode structures, or decide that
    /// a resolver is required) without performing trust evaluation or signature verification.
    /// </summary>
    KeyMaterialResolution = 0,

    /// <summary>
    /// Evaluate whether resolved key material is trusted and acceptable for the intended purpose.
    /// This can include certificate chain validation, identity checks, policy constraints, and resolver policy.
    /// </summary>
    KeyMaterialTrust = 1,

    /// <summary>
    /// Perform cryptographic signature verification (e.g., "does this signature match this public key?").
    /// </summary>
    Signature = 2,

    /// <summary>
    /// Apply additional validation that depends on a successfully verified signature.
    /// </summary>
    PostSignature = 3
}
