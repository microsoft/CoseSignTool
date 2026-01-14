// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust;

using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;

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
    /// Gets the default trust plan fragments contributed by this pack.
    /// </summary>
    /// <returns>The default fragments.</returns>
    TrustPlanDefaults GetDefaults();
}
