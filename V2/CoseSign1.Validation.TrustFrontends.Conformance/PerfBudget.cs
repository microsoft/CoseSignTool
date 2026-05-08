// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

/// <summary>
/// Statistical perf-gate helper used by the §6.5.10 #4 bounded-runtime test. Captures
/// per-iteration timing via <see cref="Stopwatch.GetTimestamp"/> (high-resolution, not
/// affected by Stopwatch's accumulated rounding), suppresses warm-up samples, and computes
/// p99 + mean.
/// </summary>
/// <remarks>
/// <para>
/// Why p99 instead of mean alone? A frontend with a JIT- or schema-warm-up cost can have
/// median latency well under budget while p99 sits 10× higher — a CI gate that only checks
/// the mean would let that regression land. Asserting both p99 ≤ 10 ms AND mean ≤ 5 ms
/// catches both shapes of regression: large outliers (covered by p99) and steady-state slow
/// drift (covered by mean).
/// </para>
/// <para>
/// Why warm-up suppression? <c>JsonSchema.Net</c> compiles its schema lazily on first use;
/// the LRU translator cache primes its hashing pipeline; the JIT promotes hot methods from
/// tier-0 to tier-1. The first few calls are not representative of steady-state cost. We
/// drop the first <see cref="AssemblyStrings.PerfWarmupIterations"/> samples and only assert
/// against the remainder.
/// </para>
/// </remarks>
public static class PerfBudget
{
    /// <summary>
    /// Times <paramref name="action"/> across the configured warm-up + measurement iteration
    /// count and returns the captured per-iteration latencies in milliseconds (warm-up
    /// samples are discarded, so the returned array's length equals
    /// <see cref="AssemblyStrings.PerfMeasuredIterations"/>).
    /// </summary>
    /// <param name="action">The action to time.</param>
    /// <returns>Per-iteration latencies, in milliseconds, sorted by sample order (not by value).</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="action"/> is null.</exception>
    public static double[] Capture(Action action)
    {
        Cose.Abstractions.Guard.ThrowIfNull(action);

        // Suppress warm-up. Iterations that ran during warm-up are NOT recorded so the
        // p99/mean math only operates on steady-state samples.
        for (int i = 0; i < AssemblyStrings.PerfWarmupIterations; i++)
        {
            action();
        }

        double[] samples = new double[AssemblyStrings.PerfMeasuredIterations];
        // Compute the per-tick conversion factor in double space so the perf gate doesn't
        // truncate sub-ms precision on platforms whose Stopwatch.Frequency is not an exact
        // multiple of 1000 (the Linux clocksource case is 1_000_000_000 hz, which is fine,
        // but the contract should hold for ARM and embedded clocks as well).
        double msPerTick = 1000.0 / Stopwatch.Frequency;

        for (int i = 0; i < samples.Length; i++)
        {
            long start = Stopwatch.GetTimestamp();
            action();
            long end = Stopwatch.GetTimestamp();
            samples[i] = (end - start) * msPerTick;
        }

        return samples;
    }

    /// <summary>
    /// Computes the arithmetic mean of <paramref name="samples"/>.
    /// </summary>
    /// <param name="samples">A non-empty sample array.</param>
    /// <returns>The mean.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="samples"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="samples"/> is empty.</exception>
    public static double Mean(IReadOnlyList<double> samples)
    {
        Cose.Abstractions.Guard.ThrowIfNull(samples);
        if (samples.Count == 0)
        {
            throw new ArgumentException(AssemblyStrings.JustifyDefensiveAdapter, nameof(samples));
        }

        double total = 0.0;
        for (int i = 0; i < samples.Count; i++)
        {
            total += samples[i];
        }

        return total / samples.Count;
    }

    /// <summary>
    /// Returns the p99 latency from <paramref name="samples"/>: sort ascending and pick the
    /// 99th-percentile bucket using nearest-rank.
    /// </summary>
    /// <param name="samples">A non-empty sample array.</param>
    /// <returns>The p99 latency.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="samples"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="samples"/> is empty.</exception>
    public static double P99(IReadOnlyList<double> samples)
    {
        Cose.Abstractions.Guard.ThrowIfNull(samples);
        if (samples.Count == 0)
        {
            throw new ArgumentException(AssemblyStrings.JustifyDefensiveAdapter, nameof(samples));
        }

        double[] sorted = new double[samples.Count];
        for (int i = 0; i < samples.Count; i++)
        {
            sorted[i] = samples[i];
        }

        Array.Sort(sorted);

        // Nearest-rank: rank = ceil(0.99 * N). For N=100, rank = 99 (1-based) → index 98.
        // We clamp to N-1 so a degenerate single-sample array still resolves.
        int rank = (int)Math.Ceiling(0.99 * sorted.Length);
        if (rank < 1)
        {
            rank = 1;
        }

        return sorted[rank - 1];
    }

    /// <summary>
    /// Formats <paramref name="samples"/> for inclusion in a failure message — useful when a
    /// CI agent reports a perf-gate failure and a developer needs to see the timing shape.
    /// </summary>
    /// <param name="samples">The samples.</param>
    /// <returns>A short stat summary (mean, p99, min, max).</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="samples"/> is null.</exception>
    public static string Summarise(IReadOnlyList<double> samples)
    {
        Cose.Abstractions.Guard.ThrowIfNull(samples);
        if (samples.Count == 0)
        {
            return AssemblyStrings.PerfNoSamplesText;
        }

        double mean = Mean(samples);
        double p99 = P99(samples);
        double min = samples[0];
        double max = samples[0];
        for (int i = 1; i < samples.Count; i++)
        {
            if (samples[i] < min)
            {
                min = samples[i];
            }

            if (samples[i] > max)
            {
                max = samples[i];
            }
        }

        return string.Format(
            CultureInfo.InvariantCulture,
            AssemblyStrings.PerfStatsFormat,
            mean,
            p99,
            min,
            max,
            samples.Count);
    }
}
