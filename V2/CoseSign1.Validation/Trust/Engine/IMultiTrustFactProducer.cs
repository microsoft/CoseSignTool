// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

/// <summary>
/// Produces facts for multiple fact types.
/// </summary>
/// <remarks>
/// This enables extension packages to provide a single producer implementation that can create a set of
/// related facts, while still allowing the engine to request individual fact types on-demand.
/// </remarks>
public interface IMultiTrustFactProducer
{
    /// <summary>
    /// Gets the fact types produced by this producer.
    /// </summary>
    IReadOnlyCollection<Type> FactTypes { get; }

    /// <summary>
    /// Produces a fact set for the requested fact type and subject.
    /// </summary>
    /// <param name="context">The fact production context.</param>
    /// <param name="factType">The requested fact type.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The produced fact set.</returns>
    ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken);
}
