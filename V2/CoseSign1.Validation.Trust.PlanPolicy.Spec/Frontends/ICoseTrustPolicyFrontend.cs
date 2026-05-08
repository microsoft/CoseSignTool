// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Frontends;

using System.Collections.Generic;

/// <summary>
/// The translation contract every CoseSign1 trust-policy frontend must satisfy (§6.5.3). A
/// frontend takes a parsed document of type <typeparamref name="TDocument"/> plus a
/// <see cref="TrustPolicyTranslationContext"/> and produces a
/// <see cref="TrustPolicyTranslationResult"/> that either carries a well-formed
/// <see cref="CoseSign1.Validation.Trust.PlanPolicy.Spec.TrustPolicySpec"/> or carries at least
/// one <see cref="TrustPolicySeverity.Error"/> diagnostic.
/// </summary>
/// <typeparam name="TDocument">The parsed document type the frontend accepts (e.g. <c>JsonDocument</c>,
/// <c>RegoDocument</c>, <c>CelExpression</c>).</typeparam>
/// <remarks>
/// <para>
/// Co-located with the IR rather than in <c>CoseSign1.Validation</c> because every frontend
/// MUST return a <see cref="CoseSign1.Validation.Trust.PlanPolicy.Spec.TrustPolicySpec"/> — and
/// because the Spec project already references <c>CoseSign1.Validation</c>, placing the
/// abstraction in <c>CoseSign1.Validation</c> would induce a project cycle. Future frontends
/// (e.g. <c>cose-tp-rego/v1</c>) reference the Spec project for the IR types and inherit the
/// abstraction at zero cost.
/// </para>
/// <para>
/// Per §6.5.4 every implementation MUST satisfy: determinism, totality, attribute fidelity,
/// reject-what-you-cant-translate, capability-aware translation, no code execution, bounded
/// runtime, and schema-checked output.
/// </para>
/// </remarks>
public interface ICoseTrustPolicyFrontend<TDocument>
{
    /// <summary>Gets the stable identifier for this frontend (e.g. <c>cose-tp-json/v1</c>).</summary>
    string FrontendId { get; }

    /// <summary>Gets the IANA media types this frontend recognises (e.g. <c>application/x-cose-trust-policy+json</c>).</summary>
    IReadOnlySet<string> SupportedMediaTypes { get; }

    /// <summary>
    /// Translates <paramref name="document"/> to a <see cref="TrustPolicyTranslationResult"/>.
    /// </summary>
    /// <param name="document">The parsed source document.</param>
    /// <param name="ctx">Translation context (parameters, fact capabilities, capability gating).</param>
    /// <returns>A result carrying the produced spec or an error diagnostic set.</returns>
    TrustPolicyTranslationResult Translate(TDocument document, TrustPolicyTranslationContext ctx);
}
