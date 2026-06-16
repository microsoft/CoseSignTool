// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Extensions;

using System.Security.Cryptography.Cose;

/// <summary>
/// Tests for <see cref="ContentDigestFormat"/> enum.
/// </summary>
[TestFixture]
public class ContentDigestFormatTests
{
    [Test]
    public void Direct_HasValue0()
    {
        Assert.That((int)ContentDigestFormat.Direct, Is.EqualTo(0));
    }

    [Test]
    public void IndirectHashLegacy_HasValue1()
    {
        Assert.That((int)ContentDigestFormat.IndirectHashLegacy, Is.EqualTo(1));
    }

    [Test]
    public void IndirectCoseHashV_HasValue2()
    {
        Assert.That((int)ContentDigestFormat.IndirectCoseHashV, Is.EqualTo(2));
    }

    [Test]
    public void IndirectCoseHashEnvelope_HasValue3()
    {
        Assert.That((int)ContentDigestFormat.IndirectCoseHashEnvelope, Is.EqualTo(3));
    }

    [Test]
    public void AllValues_AreUnique()
    {
        var values = Enum.GetValues<ContentDigestFormat>();
        Assert.That(values.Distinct().Count(), Is.EqualTo(values.Length));
    }

    [Test]
    public void AllValues_AreDefined()
    {
        Assert.That(Enum.IsDefined(ContentDigestFormat.Direct), Is.True);
        Assert.That(Enum.IsDefined(ContentDigestFormat.IndirectHashLegacy), Is.True);
        Assert.That(Enum.IsDefined(ContentDigestFormat.IndirectCoseHashV), Is.True);
        Assert.That(Enum.IsDefined(ContentDigestFormat.IndirectCoseHashEnvelope), Is.True);
    }
}