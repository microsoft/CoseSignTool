// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Extensions;

using System.Security.Cryptography.Cose;

/// <summary>
/// Tests for <see cref="SignatureFormat"/> enum.
/// </summary>
[TestFixture]
public class SignatureFormatTests
{
    [Test]
    public void Direct_HasValue0()
    {
        Assert.That((int)SignatureFormat.Direct, Is.EqualTo(0));
    }

    [Test]
    public void IndirectHashLegacy_HasValue1()
    {
        Assert.That((int)SignatureFormat.IndirectHashLegacy, Is.EqualTo(1));
    }

    [Test]
    public void IndirectCoseHashV_HasValue2()
    {
        Assert.That((int)SignatureFormat.IndirectCoseHashV, Is.EqualTo(2));
    }

    [Test]
    public void IndirectCoseHashEnvelope_HasValue3()
    {
        Assert.That((int)SignatureFormat.IndirectCoseHashEnvelope, Is.EqualTo(3));
    }

    [Test]
    public void AllValues_AreUnique()
    {
        var values = Enum.GetValues<SignatureFormat>();
        Assert.That(values.Distinct().Count(), Is.EqualTo(values.Length));
    }

    [Test]
    public void AllValues_AreDefined()
    {
        Assert.That(Enum.IsDefined(SignatureFormat.Direct), Is.True);
        Assert.That(Enum.IsDefined(SignatureFormat.IndirectHashLegacy), Is.True);
        Assert.That(Enum.IsDefined(SignatureFormat.IndirectCoseHashV), Is.True);
        Assert.That(Enum.IsDefined(SignatureFormat.IndirectCoseHashEnvelope), Is.True);
    }
}
