// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Frontends;

using System.Collections.Generic;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Output of <see cref="ICoseTrustPolicyFrontend{TDocument}.Translate"/>. Either carries a
/// well-formed <see cref="Spec"/> with no <see cref="TrustPolicySeverity.Error"/> diagnostics, or
/// carries a null <see cref="Spec"/> with at least one <see cref="TrustPolicySeverity.Error"/>
/// (totality contract per §6.5.4 #2).
/// </summary>
public sealed record TrustPolicyTranslationResult
{
    /// <summary>Gets the produced spec, or <see langword="null"/> when translation failed.</summary>
    public TrustPolicySpec? Spec { get; init; }

    /// <summary>Gets the diagnostics emitted by translation. Required (may be empty).</summary>
    public required IReadOnlyList<TrustPolicyTranslationDiagnostic> Diagnostics { get; init; }

    /// <summary>
    /// Gets a value indicating whether translation succeeded — <see cref="Spec"/> is non-null AND
    /// no diagnostic has severity <see cref="TrustPolicySeverity.Error"/>.
    /// </summary>
    public bool IsSuccess => Spec is not null && !HasError(Diagnostics);

    private static bool HasError(IReadOnlyList<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        for (int i = 0; i < diagnostics.Count; i++)
        {
            if (diagnostics[i].Severity == TrustPolicySeverity.Error)
            {
                return true;
            }
        }

        return false;
    }
}
