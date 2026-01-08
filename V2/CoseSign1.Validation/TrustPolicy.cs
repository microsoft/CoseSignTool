// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Declarative policy for determining whether the message is trusted.
/// Evaluated against a set of boolean trust claims.
/// </summary>
public abstract class TrustPolicy
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DenyAllDefaultReason = "Trust was denied because no trust policy was satisfied";
        public const string OrPolicyNoneSatisfiedReason = "None of the Or(...) trust requirements were satisfied";
        public const string NotPolicyNotSatisfiedReason = "A Not(...) trust requirement was not satisfied";
    }

    /// <summary>
    /// Evaluates whether this policy is satisfied for the provided claims.
    /// </summary>
    /// <param name="claims">A set of boolean claims keyed by claim id.</param>
    /// <returns><c>true</c> if the policy is satisfied; otherwise <c>false</c>.</returns>
    public abstract bool IsSatisfied(IReadOnlyDictionary<string, bool> claims);

    /// <summary>
    /// Adds human-readable explanations describing why the policy was or was not satisfied.
    /// </summary>
    /// <param name="claims">A set of boolean claims keyed by claim id.</param>
    /// <param name="reasons">A list to append explanatory messages to.</param>
    public abstract void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons);

    /// <summary>
    /// Creates a policy that always denies trust.
    /// </summary>
    /// <param name="reason">Optional reason explaining the denial.</param>
    /// <returns>A deny-all policy.</returns>
    public static TrustPolicy DenyAll(string? reason = null)
    {
        return new DenyAllPolicy(reason);
    }

    /// <summary>
    /// Creates a policy that always allows trust.
    /// </summary>
    /// <param name="reason">Optional reason explaining the allowance.</param>
    /// <returns>An allow-all policy.</returns>
    public static TrustPolicy AllowAll(string? reason = null)
    {
        return new AllowAllPolicy(reason);
    }

    /// <summary>
    /// Creates a policy that requires a specific claim to be satisfied.
    /// </summary>
    /// <param name="claimId">The claim id to require.</param>
    /// <returns>A claim policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="claimId"/> is null.</exception>
    public static TrustPolicy Claim(string claimId)
    {
        return new ClaimPolicy(claimId);
    }

    /// <summary>
    /// Creates a policy that is satisfied when any of the provided policies is satisfied.
    ///
    /// Note: When no policies are provided, this is vacuously satisfied.
    /// </summary>
    /// <param name="policies">The policies to evaluate.</param>
    /// <returns>An or-policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policies"/> is null.</exception>
    public static TrustPolicy Or(params TrustPolicy[] policies)
    {
        return new OrPolicy(policies);
    }

    /// <summary>
    /// Creates a policy that is satisfied only when all provided policies are satisfied.
    ///
    /// Note: When no policies are provided, this is vacuously satisfied.
    /// </summary>
    /// <param name="policies">The policies to evaluate.</param>
    /// <returns>An and-policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policies"/> is null.</exception>
    public static TrustPolicy And(params TrustPolicy[] policies)
    {
        return new AndPolicy(policies);
    }

    /// <summary>
    /// Creates a policy that inverts another policy.
    /// </summary>
    /// <param name="policy">The inner policy.</param>
    /// <returns>A negated policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policy"/> is null.</exception>
    public static TrustPolicy Not(TrustPolicy policy)
    {
        return new NotPolicy(policy);
    }

    /// <summary>
    /// Creates an implication policy: if <paramref name="ifPolicy"/> is satisfied, then <paramref name="thenPolicy"/> must be satisfied.
    /// </summary>
    /// <param name="ifPolicy">The antecedent policy.</param>
    /// <param name="thenPolicy">The consequent policy.</param>
    /// <returns>An implication policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ifPolicy"/> or <paramref name="thenPolicy"/> is null.</exception>
    public static TrustPolicy Implies(TrustPolicy ifPolicy, TrustPolicy thenPolicy)
    {
        // if => then  ==  (!if) OR then
        return Or(Not(ifPolicy), thenPolicy);
    }

    private sealed class DenyAllPolicy : TrustPolicy
    {
        private readonly string? Reason;

        public DenyAllPolicy(string? reason)
        {
            Reason = reason;
        }

        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims)
        {
            return false;
        }

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            if (!string.IsNullOrWhiteSpace(Reason))
            {
                reasons.Add(Reason!);
            }
            else
            {
                reasons.Add(ClassStrings.DenyAllDefaultReason);
            }
        }
    }

    private sealed class AllowAllPolicy : TrustPolicy
    {
        private readonly string? Reason;

        public AllowAllPolicy(string? reason)
        {
            Reason = reason;
        }

        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims)
        {
            return true;
        }

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            if (!string.IsNullOrWhiteSpace(Reason))
            {
                reasons.Add(Reason!);
            }
        }
    }

    private sealed class ClaimPolicy : TrustPolicy
    {
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        internal new static class ClassStrings
        {
            public const string ErrorFormatRequiredClaimNotSatisfied = "Required claim not satisfied: {0}";
        }

        private readonly string ClaimId;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClaimPolicy"/> class.
        /// </summary>
        /// <param name="claimId">The claim id to require.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="claimId"/> is null.</exception>
        public ClaimPolicy(string claimId)
        {
            ClaimId = claimId ?? throw new ArgumentNullException(nameof(claimId));
        }

        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims)
        {
            return claims.TryGetValue(ClaimId, out var value) && value;
        }

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            if (!IsSatisfied(claims))
            {
                reasons.Add(string.Format(ClassStrings.ErrorFormatRequiredClaimNotSatisfied, ClaimId));
            }
        }
    }

    private sealed class OrPolicy : TrustPolicy
    {
        private readonly IReadOnlyList<TrustPolicy> Policies;

        /// <summary>
        /// Initializes a new instance of the <see cref="OrPolicy"/> class.
        /// </summary>
        /// <param name="policies">The policies to evaluate.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="policies"/> is null.</exception>
        public OrPolicy(params TrustPolicy[] policies)
        {
            Policies = (policies ?? throw new ArgumentNullException(nameof(policies)))
                .Where(p => p != null)
                .ToArray();
        }

        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims)
        {
            if (Policies.Count == 0)
            {
                return true;
            }

            foreach (var p in Policies)
            {
                if (p.IsSatisfied(claims))
                {
                    return true;
                }
            }

            return false;
        }

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            if (IsSatisfied(claims))
            {
                return;
            }

            reasons.Add(ClassStrings.OrPolicyNoneSatisfiedReason);
            foreach (var p in Policies)
            {
                p.Explain(claims, reasons);
            }
        }
    }

    private sealed class AndPolicy : TrustPolicy
    {
        private readonly IReadOnlyList<TrustPolicy> Policies;

        /// <summary>
        /// Initializes a new instance of the <see cref="AndPolicy"/> class.
        /// </summary>
        /// <param name="policies">The policies to evaluate.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="policies"/> is null.</exception>
        public AndPolicy(params TrustPolicy[] policies)
        {
            Policies = (policies ?? throw new ArgumentNullException(nameof(policies)))
                .Where(p => p != null)
                .ToArray();
        }

        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims)
        {
            foreach (var p in Policies)
            {
                if (!p.IsSatisfied(claims))
                {
                    return false;
                }
            }

            return true;
        }

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            foreach (var p in Policies)
            {
                p.Explain(claims, reasons);
            }
        }
    }

    private sealed class NotPolicy : TrustPolicy
    {
        private readonly TrustPolicy Inner;

        /// <summary>
        /// Initializes a new instance of the <see cref="NotPolicy"/> class.
        /// </summary>
        /// <param name="inner">The inner policy.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="inner"/> is null.</exception>
        public NotPolicy(TrustPolicy inner)
        {
            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims)
        {
            return !Inner.IsSatisfied(claims);
        }

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            if (!IsSatisfied(claims))
            {
                reasons.Add(ClassStrings.NotPolicyNotSatisfiedReason);
            }
        }
    }
}
