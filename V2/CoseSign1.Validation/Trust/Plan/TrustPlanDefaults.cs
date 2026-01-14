// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Plan;

using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// The default trust plan fragments.
/// </summary>
public sealed class TrustPlanDefaults
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPlanDefaults"/> class.
    /// </summary>
    /// <param name="constraints">Constraints that must always hold.</param>
    /// <param name="trustSources">Trust source rules; at least one should be satisfied.</param>
    /// <param name="vetoes">Veto rules; any satisfied veto denies trust.</param>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public TrustPlanDefaults(TrustRule constraints, IReadOnlyList<TrustRule> trustSources, TrustRule vetoes)
    {
        Constraints = constraints ?? throw new ArgumentNullException(nameof(constraints));
        TrustSources = trustSources ?? throw new ArgumentNullException(nameof(trustSources));
        Vetoes = vetoes ?? throw new ArgumentNullException(nameof(vetoes));
    }

    /// <summary>
    /// Gets constraints that must always hold.
    /// </summary>
    public TrustRule Constraints { get; }

    /// <summary>
    /// Gets trust source rules; at least one should be satisfied.
    /// </summary>
    public IReadOnlyList<TrustRule> TrustSources { get; }

    /// <summary>
    /// Gets veto rules; any satisfied veto denies trust.
    /// </summary>
    public TrustRule Vetoes { get; }
}
