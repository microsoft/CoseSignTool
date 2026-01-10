// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust;

using CoseSign1.Validation.Interfaces;

/// <summary>
/// Declarative policy for determining whether a signing key is trusted.
/// </summary>
/// <remarks>
/// <para>
/// <strong>IMPORTANT:</strong> Trust originates ONLY from the policy, never from assertions.
/// Assertions are neutral facts; the policy decides which facts matter and how.
/// </para>
/// <para>
/// The policy:
/// <list type="bullet">
/// <item><description>Defines which assertions are required, optional, or disqualifying</description></item>
/// <item><description>Can require combinations (e.g., "must have valid EKU AND issuer in allowlist")</description></item>
/// <item><description>Produces a <see cref="TrustDecision"/> with clear reasons when trust is denied</description></item>
/// <item><description>Is pluggable/configurable per deployment scenario</description></item>
/// </list>
/// </para>
/// </remarks>
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
    /// Evaluates whether this policy is satisfied for the provided assertions.
    /// </summary>
    /// <param name="assertions">The signing key assertions to evaluate.</param>
    /// <returns>A <see cref="TrustDecision"/> indicating whether trust is established.</returns>
    public abstract TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions);

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
    /// Creates a policy that is satisfied when any of the provided policies is satisfied.
    /// </summary>
    /// <remarks>When no policies are provided, this is vacuously satisfied.</remarks>
    /// <param name="policies">The policies to evaluate.</param>
    /// <returns>An or-policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policies"/> is null.</exception>
    public static TrustPolicy Or(params TrustPolicy[] policies)
    {
        return new OrPolicy(policies);
    }

    /// <summary>
    /// Creates a policy that is satisfied only when all provided policies are satisfied.
    /// </summary>
    /// <remarks>When no policies are provided, this is vacuously satisfied.</remarks>
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
    /// Creates a policy that requires an assertion of the specified type to satisfy a predicate.
    /// </summary>
    /// <typeparam name="T">The assertion type to require.</typeparam>
    /// <param name="predicate">The predicate the assertion must satisfy.</param>
    /// <param name="failureReason">Human-readable reason when the policy is not satisfied.</param>
    /// <returns>A typed assertion policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> or <paramref name="failureReason"/> is null.</exception>
    public static TrustPolicy Require<T>(Func<T, bool> predicate, string failureReason) where T : class, ISigningKeyAssertion
    {
        return new RequireAssertionPolicy<T>(predicate, failureReason);
    }

    /// <summary>
    /// Creates a policy that requires an assertion of the specified type to be present (any value).
    /// </summary>
    /// <typeparam name="T">The assertion type to require.</typeparam>
    /// <param name="failureReason">Human-readable reason when the assertion is not present.</param>
    /// <returns>A typed assertion presence policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="failureReason"/> is null.</exception>
    public static TrustPolicy RequirePresent<T>(string failureReason) where T : class, ISigningKeyAssertion
    {
        return new RequireAssertionPolicy<T>(_ => true, failureReason);
    }

    /// <summary>
    /// Creates a policy that uses the default trust policy from the assertion type.
    /// </summary>
    /// <typeparam name="T">The assertion type whose default policy to use.</typeparam>
    /// <param name="assertionSample">A sample assertion instance to get the default policy from.</param>
    /// <returns>The assertion type's default policy.</returns>
    /// <remarks>
    /// This is a convenience method for using the secure-by-default policy defined by the assertion author.
    /// Prefer using the companion policy class directly (e.g., <c>X509ChainTrustPolicy.Default</c>).
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="assertionSample"/> is null.</exception>
    public static TrustPolicy UseDefault<T>(T assertionSample) where T : class, ISigningKeyAssertion
    {
        if (assertionSample == null)
        {
            throw new ArgumentNullException(nameof(assertionSample));
        }

        return assertionSample.DefaultTrustPolicy;
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

    /// <summary>
    /// Creates a policy that aggregates the default trust policies from all assertions in the set.
    /// </summary>
    /// <returns>A policy that evaluates each assertion against its own default policy.</returns>
    /// <remarks>
    /// <para>
    /// This policy is useful when you want secure-by-default behavior without explicitly
    /// specifying a trust policy. Each assertion's <see cref="ISigningKeyAssertion.DefaultTrustPolicy"/>
    /// is combined using <see cref="And"/>, requiring all default policies to be satisfied.
    /// </para>
    /// <para>
    /// If no assertions are present, this policy allows trust (vacuously satisfied).
    /// </para>
    /// </remarks>
    public static TrustPolicy FromAssertionDefaults()
    {
        return new AssertionDefaultsPolicy();
    }

    private sealed class AssertionDefaultsPolicy : TrustPolicy
    {
        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            if (assertions.Count == 0)
            {
                // No assertions means vacuously satisfied
                return TrustDecision.Trusted();
            }

            // Collect unique default policies from assertions
            // Use a set to dedupe policies that might be the same instance
            var uniquePolicies = new HashSet<TrustPolicy>();
            foreach (var assertion in assertions)
            {
                uniquePolicies.Add(assertion.DefaultTrustPolicy);
            }

            if (uniquePolicies.Count == 0)
            {
                return TrustDecision.Trusted();
            }

            // Combine all unique default policies with And
            var combinedPolicy = uniquePolicies.Count == 1
                ? uniquePolicies.First()
                : And(uniquePolicies.ToArray());

            return combinedPolicy.Evaluate(assertions);
        }
    }

    private sealed class DenyAllPolicy : TrustPolicy
    {
        private readonly string? Reason;

        public DenyAllPolicy(string? reason)
        {
            Reason = reason;
        }

        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            return TrustDecision.Denied(Reason ?? ClassStrings.DenyAllDefaultReason);
        }
    }

    private sealed class AllowAllPolicy : TrustPolicy
    {
        public AllowAllPolicy(string? reason)
        {
            // reason parameter kept for API compatibility but not used since AllowAll always trusts
        }

        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            return TrustDecision.Trusted();
        }
    }

    private sealed class OrPolicy : TrustPolicy
    {
        private readonly IReadOnlyList<TrustPolicy> Policies;

        public OrPolicy(params TrustPolicy[] policies)
        {
            Policies = (policies ?? throw new ArgumentNullException(nameof(policies)))
                .Where(p => p != null)
                .ToArray();
        }

        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            if (Policies.Count == 0)
            {
                return TrustDecision.Trusted();
            }

            var allReasons = new List<string>();
            foreach (var p in Policies)
            {
                var decision = p.Evaluate(assertions);
                if (decision.IsTrusted)
                {
                    return TrustDecision.Trusted();
                }
                allReasons.AddRange(decision.Reasons);
            }

            allReasons.Insert(0, ClassStrings.OrPolicyNoneSatisfiedReason);
            return TrustDecision.Denied(allReasons);
        }
    }

    private sealed class AndPolicy : TrustPolicy
    {
        private readonly IReadOnlyList<TrustPolicy> Policies;

        public AndPolicy(params TrustPolicy[] policies)
        {
            Policies = (policies ?? throw new ArgumentNullException(nameof(policies)))
                .Where(p => p != null)
                .ToArray();
        }

        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            var allReasons = new List<string>();
            foreach (var p in Policies)
            {
                var decision = p.Evaluate(assertions);
                if (!decision.IsTrusted)
                {
                    allReasons.AddRange(decision.Reasons);
                }
            }

            return allReasons.Count == 0 ? TrustDecision.Trusted() : TrustDecision.Denied(allReasons);
        }
    }

    private sealed class NotPolicy : TrustPolicy
    {
        private readonly TrustPolicy Inner;

        public NotPolicy(TrustPolicy inner)
        {
            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            var decision = Inner.Evaluate(assertions);
            if (decision.IsTrusted)
            {
                return TrustDecision.Denied(ClassStrings.NotPolicyNotSatisfiedReason);
            }
            return TrustDecision.Trusted();
        }
    }

    private sealed class RequireAssertionPolicy<T> : TrustPolicy where T : class, ISigningKeyAssertion
    {
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        internal new static class ClassStrings
        {
            public const string ErrorFormatAssertionNotFound = "Required assertion of type '{0}' was not found";
        }

        private readonly Func<T, bool> Predicate;
        private readonly string FailureReason;

        public RequireAssertionPolicy(Func<T, bool> predicate, string failureReason)
        {
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
            FailureReason = failureReason ?? throw new ArgumentNullException(nameof(failureReason));
        }

        public override TrustDecision Evaluate(IReadOnlyList<ISigningKeyAssertion> assertions)
        {
            var typedAssertions = assertions.OfType<T>().ToList();
            
            if (typedAssertions.Count == 0)
            {
                return TrustDecision.Denied(string.Format(ClassStrings.ErrorFormatAssertionNotFound, typeof(T).Name));
            }

            // If any assertion of this type satisfies the predicate, trust is established
            foreach (var assertion in typedAssertions)
            {
                if (Predicate(assertion))
                {
                    return TrustDecision.Trusted();
                }
            }

            return TrustDecision.Denied(FailureReason);
        }
    }
}
