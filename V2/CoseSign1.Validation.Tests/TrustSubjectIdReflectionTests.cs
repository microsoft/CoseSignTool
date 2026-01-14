// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Reflection;
using CoseSign1.Validation.Trust.Subjects;

[TestFixture]
[Category("Validation")]
public sealed class TrustSubjectIdReflectionTests
{
    [Test]
    public void PrivateCtor_WhenNullBytes_ThrowsArgumentNullException()
    {
        var ctor = typeof(TrustSubjectId).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: new[] { typeof(byte[]) },
            modifiers: null);

        Assert.That(ctor, Is.Not.Null);

        Assert.That(
            () => _ = (TrustSubjectId)ctor!.Invoke(new object?[] { null }),
            Throws.InstanceOf<TargetInvocationException>().With.InnerException.InstanceOf<ArgumentNullException>());
    }

    [Test]
    public void PrivateCtor_WhenWrongLength_ThrowsArgumentException()
    {
        var ctor = typeof(TrustSubjectId).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            types: new[] { typeof(byte[]) },
            modifiers: null);

        Assert.That(ctor, Is.Not.Null);

        Assert.That(
            () => _ = (TrustSubjectId)ctor!.Invoke(new object?[] { new byte[31] }),
            Throws.InstanceOf<TargetInvocationException>().With.InnerException.InstanceOf<ArgumentException>());
    }

    [Test]
    public void FixedTimeEquals_WhenNullLeft_ThrowsArgumentNullException()
    {
        var method = typeof(TrustSubjectId).GetMethod(
            "FixedTimeEquals",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        Assert.That(
            () => method!.Invoke(null, new object?[] { null, new byte[32] }),
            Throws.InstanceOf<TargetInvocationException>().With.InnerException.InstanceOf<ArgumentNullException>());
    }

    [Test]
    public void FixedTimeEquals_WhenNullRight_ThrowsArgumentNullException()
    {
        var method = typeof(TrustSubjectId).GetMethod(
            "FixedTimeEquals",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        Assert.That(
            () => method!.Invoke(null, new object?[] { new byte[32], null }),
            Throws.InstanceOf<TargetInvocationException>().With.InnerException.InstanceOf<ArgumentNullException>());
    }

    [Test]
    public void FixedTimeEquals_WhenDifferentLengths_ReturnsFalse()
    {
        var method = typeof(TrustSubjectId).GetMethod(
            "FixedTimeEquals",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var result = (bool)method!.Invoke(null, new object?[] { new byte[32], new byte[31] })!;

        Assert.That(result, Is.False);
    }
}
