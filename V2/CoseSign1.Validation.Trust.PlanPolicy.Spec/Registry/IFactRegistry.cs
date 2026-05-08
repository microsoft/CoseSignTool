// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Maps stable fact identifiers (e.g., <c>x509-chain-trusted/v1</c>) to their concrete CLR
/// fact types and back. The registry is the single source of truth shared by every translator,
/// the <see cref="Compilation.TrustPolicySpecCompiler"/>, and the conformance suite (Phase 4).
/// </summary>
/// <remarks>
/// Phase 1 ships a hand-rolled <see cref="StaticFactRegistry"/>; Phase 3 (<c>tp-fact-registry</c>)
/// replaces it with an attribute-driven registry that reflects <c>[TrustFactId]</c> at startup.
/// </remarks>
public interface IFactRegistry
{
    /// <summary>
    /// Resolves a fact CLR type by stable id.
    /// </summary>
    /// <param name="factId">The stable fact id.</param>
    /// <param name="clrType">When this method returns true, the resolved CLR type.</param>
    /// <returns><see langword="true"/> when <paramref name="factId"/> is registered.</returns>
    bool TryGetFactType(string factId, [NotNullWhen(true)] out Type? clrType);

    /// <summary>
    /// Resolves a stable fact id by CLR type.
    /// </summary>
    /// <param name="clrType">The CLR fact type.</param>
    /// <param name="factId">When this method returns true, the resolved id.</param>
    /// <returns><see langword="true"/> when <paramref name="clrType"/> is registered.</returns>
    bool TryGetFactId(Type clrType, [NotNullWhen(true)] out string? factId);

    /// <summary>Gets every registered fact id. Stable, lexicographic ordering for diagnostic output.</summary>
    IReadOnlySet<string> AllFactIds { get; }
}
