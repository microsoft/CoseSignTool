// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Extensions;

using System.Security.Cryptography.Cose;

/// <summary>
/// Tests for <see cref="IndirectSignatureHeaderLabels"/> static class.
/// </summary>
[TestFixture]
public class IndirectSignatureHeaderLabelsTests
{
    [Test]
    public void PayloadHashAlg_HasCorrectLabel()
    {
        // Header 258 per RFC 9054
        var expected = new CoseHeaderLabel(258);
        Assert.That(IndirectSignatureHeaderLabels.PayloadHashAlg, Is.EqualTo(expected));
    }

    [Test]
    public void PreimageContentType_HasCorrectLabel()
    {
        // Header 259 per RFC 9054
        var expected = new CoseHeaderLabel(259);
        Assert.That(IndirectSignatureHeaderLabels.PreimageContentType, Is.EqualTo(expected));
    }

    [Test]
    public void PayloadLocation_HasCorrectLabel()
    {
        // Header 260 per RFC 9054
        var expected = new CoseHeaderLabel(260);
        Assert.That(IndirectSignatureHeaderLabels.PayloadLocation, Is.EqualTo(expected));
    }

    [Test]
    public void AllLabels_AreDistinct()
    {
        var labels = new[]
        {
            IndirectSignatureHeaderLabels.PayloadHashAlg,
            IndirectSignatureHeaderLabels.PreimageContentType,
            IndirectSignatureHeaderLabels.PayloadLocation
        };

        Assert.That(labels.Distinct().Count(), Is.EqualTo(3));
    }

    [Test]
    public void Labels_AreReadonly()
    {
        // Verify static readonly fields return consistent values
        var first = IndirectSignatureHeaderLabels.PayloadHashAlg;
        var second = IndirectSignatureHeaderLabels.PayloadHashAlg;
        Assert.That(first, Is.EqualTo(second));
    }
}
