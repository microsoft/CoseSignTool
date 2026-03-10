// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Trust;

using CoseSign1.Transparent.MST.Trust;

[TestFixture]
public class MstReceiptFactTests
{
    [Test]
    public void Facts_HaveCounterSignatureScope_AndExposeValues()
    {
        var present = new MstReceiptPresentFact(IsPresent: true);
        Assert.That(present.Scope, Is.EqualTo(CoseSign1.Validation.Trust.Facts.TrustFactScope.CounterSignature));
        Assert.That(present.IsPresent, Is.True);

        var trusted = new MstReceiptTrustedFact(IsTrusted: true, Details: "ok");
        Assert.That(trusted.Scope, Is.EqualTo(CoseSign1.Validation.Trust.Facts.TrustFactScope.CounterSignature));
        Assert.That(trusted.IsTrusted, Is.True);
        Assert.That(trusted.Details, Is.EqualTo("ok"));

        var issuerHosts = new MstReceiptIssuerHostFact(new[] { "ledger.example" });
        Assert.That(issuerHosts.Scope, Is.EqualTo(CoseSign1.Validation.Trust.Facts.TrustFactScope.CounterSignature));
        Assert.That(issuerHosts.Hosts, Is.EquivalentTo(new[] { "ledger.example" }));
    }
}
