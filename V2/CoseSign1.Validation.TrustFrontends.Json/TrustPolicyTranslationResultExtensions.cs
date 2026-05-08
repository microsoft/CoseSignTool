// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json;

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

/// <summary>
/// Convenience extensions on <see cref="TrustPolicyTranslationResult"/> for the canonical
/// post-parse parameter binding step (D5).
/// </summary>
public static class TrustPolicyTranslationResultExtensions
{
    /// <summary>
    /// Substitutes every <c>$param</c> reference reachable from <see cref="TrustPolicyTranslationResult.Spec"/>
    /// with the corresponding value from <paramref name="parameters"/> (or the parameter's
    /// declared default). Returns a new <see cref="TrustPolicyTranslationResult"/>.
    /// </summary>
    /// <param name="result">The previously-translated, parameterised result.</param>
    /// <param name="parameters">Host-supplied parameter values.</param>
    /// <returns>A new result with parameters bound, or the same instance when nothing to bind.</returns>
    /// <remarks>
    /// <list type="bullet">
    ///   <item>Missing-without-default → <c>TPX400</c> (<see cref="TrustPolicyDiagnosticCodes.UnboundParameter"/>).</item>
    ///   <item><c>TPX401</c> is reserved for future strict-typed binding (e.g., when a fact
    ///         publishes a typed parameter schema and a supplied value fails it). v1 does not
    ///         emit the code; the diagnostic numbering remains stable for forward-compat.</item>
    ///   <item>If <paramref name="result"/> already carries an Error diagnostic, the same result
    ///         is returned untouched — Bind never papers over a translation error.</item>
    /// </list>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> or <paramref name="parameters"/> is null.</exception>
    public static TrustPolicyTranslationResult Bind(this TrustPolicyTranslationResult result, IReadOnlyDictionary<string, JsonNode?> parameters)
    {
        Cose.Abstractions.Guard.ThrowIfNull(result);
        Cose.Abstractions.Guard.ThrowIfNull(parameters);

        if (result.Spec is null || !result.IsSuccess)
        {
            return result;
        }

        var diagnostics = new List<TrustPolicyTranslationDiagnostic>(result.Diagnostics);
        TrustPolicySpec? bound;

        try
        {
            bound = result.Spec.Bind(parameters);
        }
        catch (TrustPolicySpecCompilationException ex) when (ex.Code == TrustPolicyDiagnosticCodes.UnboundParameter)
        {
            diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = TrustPolicyDiagnosticCodes.UnboundParameter,
                Message = ex.Message,
                Location = null,
            });
            return new TrustPolicyTranslationResult { Spec = null, Diagnostics = diagnostics };
        }

        return new TrustPolicyTranslationResult { Spec = bound, Diagnostics = diagnostics };
    }
}
