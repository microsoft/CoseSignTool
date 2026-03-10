// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Polyfills;

/// <summary>
/// Tests for <see cref="Guard"/>.
/// </summary>
[TestFixture]
public class GuardTests
{
    #region ThrowIfNull Tests

    [Test]
    public void ThrowIfNull_WithNonNullValue_DoesNotThrow()
    {
        string value = "test";

        Assert.DoesNotThrow(() => Guard.ThrowIfNull(value));
    }

    [Test]
    public void ThrowIfNull_WithNullValue_ThrowsArgumentNullException()
    {
        string? value = null;

        var ex = Assert.Throws<ArgumentNullException>(() => Guard.ThrowIfNull(value));
        Assert.That(ex.ParamName, Is.EqualTo("value"));
    }

    [Test]
    public void ThrowIfNull_WithCustomParamName_UsesCustomName()
    {
        string? value = null;

        var ex = Assert.Throws<ArgumentNullException>(() => Guard.ThrowIfNull(value, "customParam"));
        Assert.That(ex.ParamName, Is.EqualTo("customParam"));
    }

    [Test]
    public void ThrowIfNull_WithNonNullObject_DoesNotThrow()
    {
        object value = new object();

        Assert.DoesNotThrow(() => Guard.ThrowIfNull(value));
    }

    [Test]
    public void ThrowIfNull_WithNullObject_ThrowsArgumentNullException()
    {
        object? value = null;

        Assert.Throws<ArgumentNullException>(() => Guard.ThrowIfNull(value));
    }

    #endregion

    #region ThrowIfNullOrWhiteSpace Tests

    [Test]
    public void ThrowIfNullOrWhiteSpace_WithValidString_DoesNotThrow()
    {
        string value = "test";

        Assert.DoesNotThrow(() => Guard.ThrowIfNullOrWhiteSpace(value));
    }

    [Test]
    public void ThrowIfNullOrWhiteSpace_WithNullString_ThrowsArgumentNullException()
    {
        string? value = null;

        Assert.Throws<ArgumentNullException>(() => Guard.ThrowIfNullOrWhiteSpace(value));
    }

    [Test]
    public void ThrowIfNullOrWhiteSpace_WithEmptyString_ThrowsArgumentException()
    {
        string value = string.Empty;

        Assert.Throws<ArgumentException>(() => Guard.ThrowIfNullOrWhiteSpace(value));
    }

    [Test]
    public void ThrowIfNullOrWhiteSpace_WithWhiteSpaceString_ThrowsArgumentException()
    {
        string value = "   ";

        Assert.Throws<ArgumentException>(() => Guard.ThrowIfNullOrWhiteSpace(value));
    }

    [Test]
    public void ThrowIfNullOrWhiteSpace_WithTabsAndNewlines_ThrowsArgumentException()
    {
        string value = "\t\n\r  ";

        Assert.Throws<ArgumentException>(() => Guard.ThrowIfNullOrWhiteSpace(value));
    }

    [Test]
    public void ThrowIfNullOrWhiteSpace_WithCustomParamName_UsesCustomName()
    {
        string value = "";

        var ex = Assert.Throws<ArgumentException>(() => Guard.ThrowIfNullOrWhiteSpace(value, "customParam"));
        Assert.That(ex.ParamName, Is.EqualTo("customParam"));
    }

    #endregion

    #region ThrowIfDisposed Tests (object overload)

    [Test]
    public void ThrowIfDisposed_WithFalseCondition_DoesNotThrow()
    {
        bool disposed = false;
        var instance = new DisposableTestClass();

        Assert.DoesNotThrow(() => Guard.ThrowIfDisposed(disposed, instance));
    }

    [Test]
    public void ThrowIfDisposed_WithTrueCondition_ThrowsObjectDisposedException()
    {
        bool disposed = true;
        var instance = new DisposableTestClass();

        var ex = Assert.Throws<ObjectDisposedException>(() => Guard.ThrowIfDisposed(disposed, instance));
        Assert.That(ex.ObjectName, Does.Contain("DisposableTestClass"));
    }

    [Test]
    public void ThrowIfDisposed_WithNullInstance_ThrowsWithNullObjectName()
    {
        bool disposed = true;
        object? instance = null;

        var ex = Assert.Throws<ObjectDisposedException>(() => Guard.ThrowIfDisposed(disposed, instance!));
        Assert.That(ex.ObjectName, Is.Null.Or.Empty);
    }

    #endregion

    #region ThrowIfDisposed Tests (Type overload)

    [Test]
    public void ThrowIfDisposed_TypeOverload_WithFalseCondition_DoesNotThrow()
    {
        bool disposed = false;

        Assert.DoesNotThrow(() => Guard.ThrowIfDisposed(disposed, typeof(DisposableTestClass)));
    }

    [Test]
    public void ThrowIfDisposed_TypeOverload_WithTrueCondition_ThrowsObjectDisposedException()
    {
        bool disposed = true;

        var ex = Assert.Throws<ObjectDisposedException>(() => Guard.ThrowIfDisposed(disposed, typeof(DisposableTestClass)));
        Assert.That(ex.ObjectName, Does.Contain("DisposableTestClass"));
    }

    [Test]
    public void ThrowIfDisposed_TypeOverload_WithNullType_ThrowsWithNullObjectName()
    {
        bool disposed = true;
        Type? type = null;

        var ex = Assert.Throws<ObjectDisposedException>(() => Guard.ThrowIfDisposed(disposed, type!));
        Assert.That(ex.ObjectName, Is.Null.Or.Empty);
    }

    #endregion

    #region ThrowIfNullOrEmpty with Message Tests

    [Test]
    public void ThrowIfNullOrEmpty_WithMessage_ValidString_DoesNotThrow()
    {
        string value = "test";

        Assert.DoesNotThrow(() => Guard.ThrowIfNullOrEmpty(value, "custom message"));
    }

    [Test]
    public void ThrowIfNullOrEmpty_WithMessage_NullString_ThrowsArgumentException()
    {
        string? value = null;

        ArgumentException ex = Assert.Throws<ArgumentException>(() => Guard.ThrowIfNullOrEmpty(value, "must not be null"));
        Assert.That(ex.Message, Does.Contain("must not be null"));
        Assert.That(ex.ParamName, Is.EqualTo("value"));
    }

    [Test]
    public void ThrowIfNullOrEmpty_WithMessage_EmptyString_ThrowsArgumentException()
    {
        string value = string.Empty;

        ArgumentException ex = Assert.Throws<ArgumentException>(() => Guard.ThrowIfNullOrEmpty(value, "must not be empty"));
        Assert.That(ex.Message, Does.Contain("must not be empty"));
        Assert.That(ex.ParamName, Is.EqualTo("value"));
    }

    #endregion

    #region Helper Classes

    private class DisposableTestClass : IDisposable
    {
        public void Dispose() { }
    }

    #endregion
}
