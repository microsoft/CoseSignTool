// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Tests covering <see cref="TrustFactIdAttribute"/>'s id-format enforcement.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class TrustFactIdAttributeTests
{
    [Test]
    public void Constructor_ValidId_StoresIdVerbatim()
    {
        var attr = new TrustFactIdAttribute("x509-chain-trusted/v1");
        Assert.That(attr.Id, Is.EqualTo("x509-chain-trusted/v1"));
    }

    [Test]
    public void Constructor_MultiSegmentKebabId_Accepted()
    {
        var attr = new TrustFactIdAttribute("mst-receipt-issuer-host/v42");
        Assert.That(attr.Id, Is.EqualTo("mst-receipt-issuer-host/v42"));
    }

    [Test]
    public void Constructor_NullId_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new TrustFactIdAttribute(null!));
    }

    [Test]
    public void Constructor_EmptyId_Throws()
    {
        Assert.Catch<ArgumentException>(() => new TrustFactIdAttribute(string.Empty));
    }

    [Test]
    public void Constructor_WhitespaceId_Throws()
    {
        Assert.Catch<ArgumentException>(() => new TrustFactIdAttribute("   "));
    }

    [TestCase("X509-chain/v1", Description = "Uppercase letter")]
    [TestCase("1leading-digit/v1", Description = "Leading digit")]
    [TestCase("missing-version", Description = "No /vN suffix")]
    [TestCase("name/v", Description = "Empty version digits")]
    [TestCase("name/version1", Description = "Version not '/v<digits>'")]
    [TestCase("name/v1.0", Description = "Decimal version")]
    [TestCase("a b/v1", Description = "Space inside id")]
    [TestCase("/v1", Description = "Empty kebab segment")]
    [TestCase("name//v1", Description = "Double slash")]
    public void Constructor_MalformedId_Throws(string id)
    {
        Assert.Throws<ArgumentException>(() => new TrustFactIdAttribute(id));
    }

    [Test]
    public void Constructor_TrailingDashId_IsAccepted()
    {
        // The regex [a-z][a-z0-9-]*\/v[0-9]+ permits a trailing dash before the version slash.
        // The choice is intentional — easier-to-read ids like 'foo-bar-/v1' would be rare in
        // practice but not malformed by the spec.
        Assert.That(new TrustFactIdAttribute("trailing-dash-/v1").Id, Is.EqualTo("trailing-dash-/v1"));
    }

    [TestCase("x509-chain-trusted/v1")]
    [TestCase("mst-receipt-trusted/v2")]
    [TestCase("a/v0")]
    [TestCase("a-b-c/v100")]
    public void Constructor_AcceptedIds_RoundTrip(string id)
    {
        Assert.That(new TrustFactIdAttribute(id).Id, Is.EqualTo(id));
    }

    [Test]
    public void IdPattern_Constant_IsExposed()
    {
        // Public regex source — frontends and tooling can use the same pattern in their own
        // schema validation without a circular dependency on this assembly's regex engine.
        Assert.That(TrustFactIdAttribute.IdPattern, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public void Attribute_IsApplied_ToKnownFact()
    {
        var attr = (TrustFactIdAttribute?)Attribute.GetCustomAttribute(
            typeof(CoseSign1.Certificates.Trust.Facts.X509ChainTrustedFact),
            typeof(TrustFactIdAttribute));
        Assert.That(attr, Is.Not.Null);
        Assert.That(attr!.Id, Is.EqualTo("x509-chain-trusted/v1"));
    }
}
