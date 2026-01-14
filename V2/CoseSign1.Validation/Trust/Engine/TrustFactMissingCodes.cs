// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

/// <summary>
/// Stable missing-reason codes used by the trust fact engine.
/// </summary>
public static class TrustFactMissingCodes
{
    internal static class ClassStrings
    {
        public const string NoProducers = "NO_PRODUCERS";
        public const string Cancelled = "CANCELLED";
        public const string BudgetExceeded = "BUDGET_EXCEEDED";
        public const string ProducerFailed = "PRODUCER_FAILED";
        public const string AllProducersMissing = "ALL_PRODUCERS_MISSING";
        public const string InputUnavailable = "INPUT_UNAVAILABLE";
    }

    /// <summary>
    /// No producers were registered for the requested fact type.
    /// </summary>
    public const string NoProducers = ClassStrings.NoProducers;

    /// <summary>
    /// Fact production was cancelled.
    /// </summary>
    public const string Cancelled = ClassStrings.Cancelled;

    /// <summary>
    /// Fact production exceeded a configured budget.
    /// </summary>
    public const string BudgetExceeded = ClassStrings.BudgetExceeded;

    /// <summary>
    /// A producer threw an exception while producing facts.
    /// </summary>
    public const string ProducerFailed = ClassStrings.ProducerFailed;

    /// <summary>
    /// All producers returned missing for the requested fact.
    /// </summary>
    public const string AllProducersMissing = ClassStrings.AllProducersMissing;

    /// <summary>
    /// Required input data was not available to producers (for example, message bytes/headers).
    /// </summary>
    public const string InputUnavailable = ClassStrings.InputUnavailable;
}
