// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;

/// <summary>
/// Terminal: always trusted. Mirrors <see cref="CoseSign1.Validation.Trust.Rules.TrustRules.AllowAll"/>.
/// </summary>
public sealed record AllowAllSpec : TrustPolicySpec;
