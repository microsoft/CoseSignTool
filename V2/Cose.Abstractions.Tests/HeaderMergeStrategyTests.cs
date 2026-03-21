// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Cose.Abstractions.Tests;

using Cose.Abstractions;

/// <summary>
/// Tests for <see cref="HeaderMergeStrategy"/> enum.
/// </summary>
[TestFixture]
public class HeaderMergeStrategyTests
{
    [Test]
    public void Fail_HasValue0()
    {
        Assert.That((int)HeaderMergeStrategy.Fail, Is.EqualTo(0));
    }

    [Test]
    public void KeepExisting_HasValue1()
    {
        Assert.That((int)HeaderMergeStrategy.KeepExisting, Is.EqualTo(1));
    }

    [Test]
    public void Replace_HasValue2()
    {
        Assert.That((int)HeaderMergeStrategy.Replace, Is.EqualTo(2));
    }

    [Test]
    public void Custom_HasValue3()
    {
        Assert.That((int)HeaderMergeStrategy.Custom, Is.EqualTo(3));
    }

    [Test]
    public void AllValues_AreDefined()
    {
        string[] names = Enum.GetNames(typeof(HeaderMergeStrategy));
        Assert.That(names, Has.Length.EqualTo(4));
        Assert.That(names, Does.Contain("Fail"));
        Assert.That(names, Does.Contain("KeepExisting"));
        Assert.That(names, Does.Contain("Replace"));
        Assert.That(names, Does.Contain("Custom"));
    }
}