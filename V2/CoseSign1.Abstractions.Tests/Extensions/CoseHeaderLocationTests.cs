// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Extensions;

using System.Security.Cryptography.Cose;

/// <summary>
/// Tests for <see cref="CoseHeaderLocation"/> enum.
/// </summary>
[TestFixture]
public class CoseHeaderLocationTests
{
    [Test]
    public void Protected_HasValue1()
    {
        Assert.That((int)CoseHeaderLocation.Protected, Is.EqualTo(1));
    }

    [Test]
    public void Unprotected_HasValue2()
    {
        Assert.That((int)CoseHeaderLocation.Unprotected, Is.EqualTo(2));
    }

    [Test]
    public void Any_IsCombinationOfProtectedAndUnprotected()
    {
        Assert.That(CoseHeaderLocation.Any, Is.EqualTo(CoseHeaderLocation.Protected | CoseHeaderLocation.Unprotected));
        Assert.That((int)CoseHeaderLocation.Any, Is.EqualTo(3));
    }

    [Test]
    public void Any_HasFlagProtected_ReturnsTrue()
    {
        Assert.That(CoseHeaderLocation.Any.HasFlag(CoseHeaderLocation.Protected), Is.True);
    }

    [Test]
    public void Any_HasFlagUnprotected_ReturnsTrue()
    {
        Assert.That(CoseHeaderLocation.Any.HasFlag(CoseHeaderLocation.Unprotected), Is.True);
    }

    [Test]
    public void Protected_HasFlagUnprotected_ReturnsFalse()
    {
        Assert.That(CoseHeaderLocation.Protected.HasFlag(CoseHeaderLocation.Unprotected), Is.False);
    }

    [Test]
    public void Unprotected_HasFlagProtected_ReturnsFalse()
    {
        Assert.That(CoseHeaderLocation.Unprotected.HasFlag(CoseHeaderLocation.Protected), Is.False);
    }

    [Test]
    public void FlagsAttribute_AllowsBitwiseOperations()
    {
        var combined = CoseHeaderLocation.Protected | CoseHeaderLocation.Unprotected;
        Assert.That(combined, Is.EqualTo(CoseHeaderLocation.Any));
    }
}
