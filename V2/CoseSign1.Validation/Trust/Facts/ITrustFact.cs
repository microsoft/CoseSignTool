// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Base interface for all trust facts.
/// </summary>
/// <remarks>
/// This interface provides explicit runtime metadata shared across all fact categories.
/// Scope-specific marker interfaces (e.g., <see cref="IMessageFact"/>) exist for compile-time scoping.
/// </remarks>
public interface ITrustFact
{
	/// <summary>
	/// Gets the policy scope this fact is intended for.
	/// </summary>
	TrustFactScope Scope { get; }
}
