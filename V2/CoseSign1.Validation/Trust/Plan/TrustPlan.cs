// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Plan;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Audit;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;

/// <summary>
/// A compiled trust plan with an evaluation root and associated fact producers.
/// </summary>
public sealed class CompiledTrustPlan
{
    private readonly TrustRule Root;
    private readonly IReadOnlyList<IMultiTrustFactProducer> Producers;
    private readonly IServiceProvider? Services;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorMissingTrustPacks = "No ITrustPack was registered";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CompiledTrustPlan"/> class.
    /// </summary>
    /// <param name="root">The root rule.</param>
    /// <param name="producers">The fact producers available to this plan.</param>
    /// <param name="services">Optional service provider for resolving producer dependencies.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="root"/> or <paramref name="producers"/> is null.</exception>
    public CompiledTrustPlan(TrustRule root, IReadOnlyList<IMultiTrustFactProducer> producers, IServiceProvider? services = null)
    {
        Guard.ThrowIfNull(root);
        Guard.ThrowIfNull(producers);

        Root = root;
        Producers = producers;
        Services = services;
    }

    /// <summary>
    /// Compiles the default trust plan from the given service provider.
    /// </summary>
    /// <param name="services">The service provider.</param>
    /// <returns>A compiled trust plan.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no defaults provider is registered.</exception>
    public static CompiledTrustPlan CompileDefaults(IServiceProvider services)
    {
        Guard.ThrowIfNull(services);

        // Trust packs contribute defaults via ITrustPack registrations.
        // We intentionally support multiple packs so that each extension package can contribute
        // secure-by-default fragments without requiring a single central coordinator.
        var packs = (services.GetService(typeof(IEnumerable<ITrustPack>)) as IEnumerable<ITrustPack>)
            ?.ToArray();

        if (packs == null || packs.Length == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorMissingTrustPacks);
        }

        var defaults = ComposeDefaults(packs);

        var root = TrustRules.And(
            defaults.Constraints,
            TrustRules.Or(defaults.TrustSources.ToArray()),
            TrustRules.Not(defaults.Vetoes));

        return new CompiledTrustPlan(root, packs, services);
    }

    private static TrustPlanDefaults ComposeDefaults(IReadOnlyList<ITrustPack> packs)
    {
        Guard.ThrowIfNull(packs);

        if (packs.Count == 1)
        {
            return packs[0].GetDefaults();
        }

        var constraints = new List<TrustRule>(capacity: packs.Count);
        var trustSources = new List<TrustRule>();
        var vetoes = new List<TrustRule>(capacity: packs.Count);

        foreach (var pack in packs)
        {
            var defaults = pack.GetDefaults();
            constraints.Add(defaults.Constraints);
            trustSources.AddRange(defaults.TrustSources);
            vetoes.Add(defaults.Vetoes);
        }

        return new TrustPlanDefaults(
            constraints: TrustRules.And(constraints.ToArray()),
            trustSources: trustSources,
            vetoes: TrustRules.Or(vetoes.ToArray()));
    }

    /// <summary>
    /// Evaluates the plan synchronously.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The trust decision.</returns>
    public TrustDecision Evaluate(
        TrustSubjectId messageId,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        return EvaluateAsync(messageId, subject, options, memoryCache, cancellationToken)
            .AsTask().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Evaluates the plan synchronously using the current message as input for fact production.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="message">The current COSE Sign1 message.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The trust decision.</returns>
    public TrustDecision Evaluate(
        TrustSubjectId messageId,
        CoseSign1Message message,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        return EvaluateAsync(messageId, message, subject, options, memoryCache, cancellationToken)
            .AsTask().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Evaluates the plan asynchronously.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The trust decision.</returns>
    public async ValueTask<TrustDecision> EvaluateAsync(
        TrustSubjectId messageId,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        var factEngine = new TrustFactEngine(messageId, Producers, options, memoryCache, cancellationToken, services: Services);
        var context = new TrustRuleContext(factEngine, subject);
        return await Root.EvaluateAsync(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Evaluates the plan asynchronously using the current message as input for fact production.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="message">The current COSE Sign1 message.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The trust decision.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    public async ValueTask<TrustDecision> EvaluateAsync(
        TrustSubjectId messageId,
        CoseSign1Message message,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);

        var factEngine = new TrustFactEngine(messageId, message, Producers, options, memoryCache, cancellationToken, services: Services);
        var context = new TrustRuleContext(factEngine, subject);
        return await Root.EvaluateAsync(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Evaluates the plan synchronously and produces an audit.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The evaluation result including an audit.</returns>
    public TrustPlanEvaluationResult EvaluateWithAudit(
        TrustSubjectId messageId,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        return EvaluateWithAuditAsync(messageId, subject, options, memoryCache, cancellationToken)
            .AsTask().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Evaluates the plan synchronously, produces an audit, and provides the current message to fact producers.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="message">The current COSE Sign1 message.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The evaluation result including an audit.</returns>
    public TrustPlanEvaluationResult EvaluateWithAudit(
        TrustSubjectId messageId,
        CoseSign1Message message,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        return EvaluateWithAuditAsync(messageId, message, subject, options, memoryCache, cancellationToken)
            .AsTask().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Evaluates the plan asynchronously and produces an audit.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The evaluation result including an audit.</returns>
    public async ValueTask<TrustPlanEvaluationResult> EvaluateWithAuditAsync(
        TrustSubjectId messageId,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        var auditBuilder = new TrustDecisionAuditBuilder();

        var factEngine = new TrustFactEngine(messageId, Producers, options, memoryCache, cancellationToken, services: Services);
        var context = new TrustRuleContext(factEngine, subject, auditBuilder);

        var decision = await Root.EvaluateAsync(context).ConfigureAwait(false);
        var audit = auditBuilder.Build(messageId, subject, decision);
        return new TrustPlanEvaluationResult(decision, audit);
    }

    /// <summary>
    /// Evaluates the plan asynchronously, produces an audit, and provides the current message to fact producers.
    /// </summary>
    /// <param name="messageId">The stable message ID.</param>
    /// <param name="message">The current COSE Sign1 message.</param>
    /// <param name="subject">The subject to evaluate.</param>
    /// <param name="options">Optional evaluation options.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The evaluation result including an audit.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    public async ValueTask<TrustPlanEvaluationResult> EvaluateWithAuditAsync(
        TrustSubjectId messageId,
        CoseSign1Message message,
        TrustSubject subject,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);

        var auditBuilder = new TrustDecisionAuditBuilder();

        var factEngine = new TrustFactEngine(messageId, message, Producers, options, memoryCache, cancellationToken, services: Services);
        var context = new TrustRuleContext(factEngine, subject, auditBuilder);

        var decision = await Root.EvaluateAsync(context).ConfigureAwait(false);
        var audit = auditBuilder.Build(messageId, subject, decision);
        return new TrustPlanEvaluationResult(decision, audit);
    }
}
