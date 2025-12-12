// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

using CoseSign1.Headers;

/// <summary>
/// Unit tests for <see cref="ChainedCoseHeaderExtender"/>.
/// </summary>
public class ChainedCoseHeaderExtenderTests
{
    /// <summary>
    /// Dummy implementation of <see cref="ICoseHeaderExtender"/> for testing chaining behavior.
    /// </summary>
    private class DummyExtender : ICoseHeaderExtender
    {
        private readonly Func<CoseHeaderMap, CoseHeaderMap> Protected;
        private readonly Func<CoseHeaderMap?, CoseHeaderMap> Unprotected;
        /// <summary>
        /// Initializes a new instance of the <see cref="DummyExtender"/> class.
        /// </summary>
        /// <param name="protectedFunc">Delegate to handle <see cref="ExtendProtectedHeaders"/>.</param>
        /// <param name="unprotectedFunc">Delegate to handle <see cref="ExtendUnProtectedHeaders"/>.</param>
        public DummyExtender(Func<CoseHeaderMap, CoseHeaderMap> protectedFunc, Func<CoseHeaderMap?, CoseHeaderMap> unprotectedFunc)
        {
            Protected = protectedFunc;
            Unprotected = unprotectedFunc;
        }
        /// <inheritdoc/>
        public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders) => Protected(protectedHeaders);
        /// <inheritdoc/>
        public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders) => Unprotected(unProtectedHeaders);
    }

    [Test]
    public void Constructor_ThrowsOnNullEnumerable()
    {
        Assert.Throws<ArgumentNullException>(() => new ChainedCoseHeaderExtender(null!));
    }

    [Test]
    public void Constructor_ThrowsOnNullElement()
    {
        ICoseHeaderExtender[] extenders = new ICoseHeaderExtender[] { new DummyExtender(h => h, h => h!), null! };
        Assert.Throws<ArgumentException>(() => new ChainedCoseHeaderExtender(extenders));
    }

    [Test]
    public void ExtendProtectedHeaders_ThrowsOnNullInput()
    {
        ChainedCoseHeaderExtender chain = new ChainedCoseHeaderExtender(new[] { new DummyExtender(h => h, h => h) });
        Assert.Throws<ArgumentNullException>(() => chain.ExtendProtectedHeaders(null));
    }

    [Test]
    public void ExtendProtectedHeaders_ThrowsIfAnyExtenderReturnsNull()
    {
        ICoseHeaderExtender[] extenders = new ICoseHeaderExtender[] {
            new DummyExtender(h => h, h => h),
            new DummyExtender(h => null, h => h)
        };
        ChainedCoseHeaderExtender chain = new ChainedCoseHeaderExtender(extenders);
        Assert.Throws<InvalidOperationException>(() => chain.ExtendProtectedHeaders(new CoseHeaderMap()));
    }

    [Test]
    public void ExtendUnProtectedHeaders_ThrowsIfAnyExtenderReturnsNull()
    {
        ICoseHeaderExtender[] extenders = new ICoseHeaderExtender[] {
            new DummyExtender(h => h, h => h),
            new DummyExtender(h => h, h => null)
        };
        ChainedCoseHeaderExtender chain = new ChainedCoseHeaderExtender(extenders);
        Assert.Throws<InvalidOperationException>(() => chain.ExtendUnProtectedHeaders(new CoseHeaderMap()));
    }

    [Test]
    public void ExtendProtectedHeaders_ChainsCorrectly()
    {
        ChainedCoseHeaderExtender chain = new ChainedCoseHeaderExtender(new ICoseHeaderExtender[] {
            new DummyExtender(h => { h[new CoseHeaderLabel("a")] = CoseHeaderValue.FromInt32(1); return h; }, h => h!),
            new DummyExtender(h => { h[new CoseHeaderLabel("b")] = CoseHeaderValue.FromInt32(2); return h; }, h => h!)
        });
        CoseHeaderMap map = new CoseHeaderMap();
        CoseHeaderMap result = chain.ExtendProtectedHeaders(map);
        result[new CoseHeaderLabel("a")].GetValueAsInt32().Should().Be(1);
        result[new CoseHeaderLabel("b")].GetValueAsInt32().Should().Be(2);
    }

    [Test]
    public void ExtendUnProtectedHeaders_ChainsCorrectly()
    {
        ChainedCoseHeaderExtender chain = new ChainedCoseHeaderExtender(new ICoseHeaderExtender[] {
            new DummyExtender(h => h, h => { h![new CoseHeaderLabel("x")] = CoseHeaderValue.FromInt32(10); return h; }),
            new DummyExtender(h => h, h => { h![new CoseHeaderLabel("y")] = CoseHeaderValue.FromInt32(20); return h; })
        });
        CoseHeaderMap map = new CoseHeaderMap();
        CoseHeaderMap result = chain.ExtendUnProtectedHeaders(map);
        result[new CoseHeaderLabel("x")].GetValueAsInt32().Should().Be(10);
        result[new CoseHeaderLabel("y")].GetValueAsInt32().Should().Be(20);
    }
}

