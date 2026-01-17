// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Rules;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Audit;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Context provided to trust rules during evaluation.
/// </summary>
public sealed class TrustRuleContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustRuleContext"/> class.
    /// </summary>
    /// <param name="facts">The fact engine for this evaluation.</param>
    /// <param name="subject">The current subject.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="facts"/> or <paramref name="subject"/> is null.</exception>
    public TrustRuleContext(TrustFactEngine facts, TrustSubject subject)
    {
        Guard.ThrowIfNull(facts);
        Guard.ThrowIfNull(subject);

        Facts = facts;
        Subject = subject;
        Audit = null;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustRuleContext"/> class.
    /// </summary>
    /// <param name="facts">The fact engine for this evaluation.</param>
    /// <param name="subject">The current subject.</param>
    /// <param name="audit">The audit builder to record evaluation events.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="facts"/> or <paramref name="subject"/> is null.</exception>
    internal TrustRuleContext(TrustFactEngine facts, TrustSubject subject, TrustDecisionAuditBuilder audit)
    {
        Guard.ThrowIfNull(facts);
        Guard.ThrowIfNull(subject);
        Guard.ThrowIfNull(audit);

        Facts = facts;
        Subject = subject;
        Audit = audit;
    }

    /// <summary>
    /// Gets the fact engine for this evaluation.
    /// </summary>
    public TrustFactEngine Facts { get; }

    /// <summary>
    /// Gets the current subject.
    /// </summary>
    public TrustSubject Subject { get; }

    /// <summary>
    /// Gets the audit builder (if auditing is enabled).
    /// </summary>
    internal TrustDecisionAuditBuilder? Audit { get; }
}
