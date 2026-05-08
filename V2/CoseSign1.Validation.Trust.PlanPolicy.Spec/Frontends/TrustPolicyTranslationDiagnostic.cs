// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Frontends;

using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

/// <summary>
/// One observation produced by a frontend's <see cref="ICoseTrustPolicyFrontend{TDocument}.Translate"/>
/// pass. Diagnostics carry a stable code drawn from <see cref="TrustPolicyDiagnosticCodes"/> so
/// callers can switch on the failure category without parsing the human-readable message.
/// </summary>
public sealed record TrustPolicyTranslationDiagnostic
{
    /// <summary>Gets the severity of this diagnostic. Required.</summary>
    public required TrustPolicySeverity Severity { get; init; }

    /// <summary>Gets the stable diagnostic code, e.g. <c>TPX100</c>. Required.</summary>
    public required string Code { get; init; }

    /// <summary>Gets the human-readable message naming the offending construct. Required.</summary>
    public required string Message { get; init; }

    /// <summary>Gets the optional source location pointing at the offending site in the source document.</summary>
    public required SourceLocation? Location { get; init; }

    /// <summary>Gets an optional remediation hint surfaced to authors next to the message.</summary>
    public string? Suggestion { get; init; }
}
