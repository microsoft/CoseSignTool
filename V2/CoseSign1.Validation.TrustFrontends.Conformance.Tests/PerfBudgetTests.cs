// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System;
using System.Linq;
using System.Threading;

[TestFixture]
public sealed class PerfBudgetTests
{
    [Test]
    public void Capture_NullAction_Throws()
    {
        Assert.That(() => PerfBudget.Capture(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Capture_RetainsOnlyMeasuredIterations()
    {
        // The captured array's length is the post-warmup measured iteration count. We
        // verify that the warm-up samples were dropped and exactly the measured count is
        // returned.
        double[] samples = PerfBudget.Capture(static () => Thread.SpinWait(50));

        Assert.That(samples.Length, Is.EqualTo(100));
        Assert.That(samples.All(s => s >= 0.0), Is.True);
    }

    [Test]
    public void Mean_NullSamples_Throws()
    {
        Assert.That(() => PerfBudget.Mean(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Mean_EmptySamples_Throws()
    {
        Assert.That(() => PerfBudget.Mean(Array.Empty<double>()), Throws.ArgumentException);
    }

    [Test]
    public void Mean_ComputesAverage()
    {
        double mean = PerfBudget.Mean(new double[] { 1.0, 2.0, 3.0, 4.0 });

        Assert.That(mean, Is.EqualTo(2.5).Within(1e-9));
    }

    [Test]
    public void P99_NullSamples_Throws()
    {
        Assert.That(() => PerfBudget.P99(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void P99_EmptySamples_Throws()
    {
        Assert.That(() => PerfBudget.P99(Array.Empty<double>()), Throws.ArgumentException);
    }

    [Test]
    public void P99_OnHundredSamples_PicksRank99()
    {
        // ascending [1..100] → p99 (nearest-rank with rank=99) is the 99th sample which equals 99.
        double[] samples = Enumerable.Range(1, 100).Select(static i => (double)i).ToArray();
        double p99 = PerfBudget.P99(samples);

        Assert.That(p99, Is.EqualTo(99.0).Within(1e-9));
    }

    [Test]
    public void P99_OnSingleSample_ReturnsThatSample()
    {
        double p99 = PerfBudget.P99(new double[] { 42.0 });

        Assert.That(p99, Is.EqualTo(42.0).Within(1e-9));
    }

    [Test]
    public void Summarise_NullSamples_Throws()
    {
        Assert.That(() => PerfBudget.Summarise(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Summarise_EmptySamples_ReturnsNoSamplesText()
    {
        Assert.That(PerfBudget.Summarise(Array.Empty<double>()), Does.Contain("no samples"));
    }

    [Test]
    public void Summarise_NonEmpty_IncludesMeanAndP99()
    {
        string text = PerfBudget.Summarise(new double[] { 1.0, 2.0, 3.0, 4.0, 5.0 });

        Assert.That(text, Does.Contain("mean="));
        Assert.That(text, Does.Contain("p99="));
        Assert.That(text, Does.Contain("min="));
        Assert.That(text, Does.Contain("max="));
        Assert.That(text, Does.Contain("n=5"));
    }

    [Test]
    public void Summarise_TracksMinAndMaxAcrossUnsortedSamples()
    {
        // Min/max walk runs over the input order; samples here are not sorted, so the
        // walker has to track both extremes.
        string text = PerfBudget.Summarise(new double[] { 3.0, 1.0, 5.0, 2.0, 4.0 });

        Assert.That(text, Does.Contain("min=1"));
        Assert.That(text, Does.Contain("max=5"));
    }
}
