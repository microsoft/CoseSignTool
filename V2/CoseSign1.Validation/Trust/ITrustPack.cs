// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust;

using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// A trust pack contributes both fact production and secure-by-default trust plan fragments.
/// </summary>
/// <remarks>
/// This interface is the preferred registration surface for extension packages.
/// It ensures each pack that can produce facts also exposes its default policy contribution.
/// </remarks>
public interface ITrustPack : IMultiTrustFactProducer
{
    /// <summary>
    /// Gets the signing key resolver that is tightly coupled to this trust pack, if any.
    /// </summary>
    /// <remarks>
    /// Many trust packs assume a specific key-material source (for example, x5chain or Key Vault).
    /// Exposing the resolver here allows an extension package to register a single <see cref="ITrustPack"/>
    /// and still participate fully in staged validation.
    /// </remarks>
    ISigningKeyResolver? SigningKeyResolver { get; }

    /// <summary>
    /// Gets the default trust plan fragments contributed by this pack.
    /// </summary>
    /// <returns>The default fragments.</returns>
    TrustPlanDefaults GetDefaults();
}
