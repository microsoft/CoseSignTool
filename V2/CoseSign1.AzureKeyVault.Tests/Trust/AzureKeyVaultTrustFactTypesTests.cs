// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Trust;

using CoseSign1.AzureKeyVault.Trust;

[TestFixture]
public class AzureKeyVaultTrustFactTypesTests
{
    [Test]
    public void Facts_HaveSigningKeyScope_AndExposeValues()
    {
        var detected = new AzureKeyVaultKidDetectedFact(IsAzureKeyVaultKey: true);
        Assert.That(detected.Scope, Is.EqualTo(CoseSign1.Validation.Trust.Facts.TrustFactScope.Message));
        Assert.That(detected.IsAzureKeyVaultKey, Is.True);

        var allowed = new AzureKeyVaultKidAllowedFact(IsAllowed: true, Details: "ok");
        Assert.That(allowed.Scope, Is.EqualTo(CoseSign1.Validation.Trust.Facts.TrustFactScope.Message));
        Assert.That(allowed.IsAllowed, Is.True);
        Assert.That(allowed.Details, Is.EqualTo("ok"));
    }
}
