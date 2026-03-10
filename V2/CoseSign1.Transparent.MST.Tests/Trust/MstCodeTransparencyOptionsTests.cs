// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Trust;

using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Trust;

[TestFixture]
public sealed class MstCodeTransparencyOptionsTests
{
    [Test]
    public void CreateVerificationOptions_WhenAuthorizedDomainsIsNull_UsesVerifyAll()
    {
        var options = new MstTrustOptions { AuthorizedDomains = null };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.That(verificationOptions.AuthorizedDomains, Is.Null);
        Assert.That(verificationOptions.UnauthorizedReceiptBehavior, Is.EqualTo(UnauthorizedReceiptBehavior.VerifyAll));
    }

    [Test]
    public void CreateVerificationOptions_WhenAuthorizedDomainsIsEmpty_UsesVerifyAll()
    {
        var options = new MstTrustOptions { AuthorizedDomains = Array.Empty<string>() };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.That(verificationOptions.AuthorizedDomains, Is.Empty);
        Assert.That(verificationOptions.UnauthorizedReceiptBehavior, Is.EqualTo(UnauthorizedReceiptBehavior.VerifyAll));
    }

    [Test]
    public void CreateVerificationOptions_WhenAuthorizedDomainsProvided_UsesFailIfPresent()
    {
        var options = new MstTrustOptions { AuthorizedDomains = new[] { "ledger.example" } };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.That(verificationOptions.AuthorizedDomains, Is.EquivalentTo(new[] { "ledger.example" }));
        Assert.That(verificationOptions.UnauthorizedReceiptBehavior, Is.EqualTo(UnauthorizedReceiptBehavior.FailIfPresent));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndJwksNotConfigured_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = null,
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.Throws<InvalidOperationException>(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyWithValidJwks_SetsOfflineKeysAndDisablesNetworkFallback()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        MstCodeTransparencyOptions.ConfigureOfflineKeys(
            verificationOptions,
            options,
            issuerHosts: new[] { "ledger.example" });

        Assert.That(verificationOptions.OfflineKeys, Is.Not.Null);
        Assert.That(verificationOptions.OfflineKeysBehavior, Is.EqualTo(OfflineKeysBehavior.NoFallbackToNetwork));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndNoIssuerHostsStillDisablesNetworkFallback()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        MstCodeTransparencyOptions.ConfigureOfflineKeys(
            verificationOptions,
            options,
            issuerHosts: Array.Empty<string>());

        Assert.That(verificationOptions.OfflineKeys, Is.Not.Null);
        Assert.That(verificationOptions.OfflineKeysBehavior, Is.EqualTo(OfflineKeysBehavior.NoFallbackToNetwork));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenNotOfflineOnly_DoesNothing()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = false,
            OfflineTrustedJwksJson = null,
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.DoesNotThrow(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));

        Assert.That(verificationOptions.OfflineKeys, Is.Null);
    }

    [Test]
    public void TryCreateClientOptionsForOfflineJwks_WhenNotOfflineOnly_ReturnsNull()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = false,
            OfflineTrustedJwksJson = null,
        };

        var clientOptions = MstCodeTransparencyOptions.TryCreateClientOptionsForOfflineJwks(options);

        Assert.That(clientOptions, Is.Null);
    }

    [Test]
    public void TryCreateClientOptionsForOfflineJwks_WhenOfflineOnlyAndJwksNotConfigured_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = null,
        };

        Assert.Throws<InvalidOperationException>(() => MstCodeTransparencyOptions.TryCreateClientOptionsForOfflineJwks(options));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndJwksNotAnObject_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "[]",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.Throws<InvalidOperationException>(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndKeysMissing_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.Throws<InvalidOperationException>(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndKeysNotArray_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{\"keys\":{}}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.Throws<InvalidOperationException>(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndKeysEmpty_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{\"keys\":[]}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.Throws<InvalidOperationException>(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndNoKeyHasKty_Throws()
    {
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{\"keys\":[{\"kid\":\"k1\"}]}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.Throws<InvalidOperationException>(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "ledger.example" }));
    }

    [Test]
    public void ConfigureOfflineKeys_WhenOfflineOnlyAndMixedKeyEntries_SucceedsAndDisablesNetworkFallback()
    {
        // Covers: non-object entries, keys with missing kty, x5c parsing, and host filtering.
        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = "{\"keys\":[\"not-an-object\",{\"kid\":\"skip-no-kty\"},{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"x5c\":[\"cert\",\"  \",123]}]}",
        };

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(options);

        Assert.DoesNotThrow(() =>
            MstCodeTransparencyOptions.ConfigureOfflineKeys(
                verificationOptions,
                options,
                issuerHosts: new[] { "", "  ", "ledger.example" }));

        Assert.That(verificationOptions.OfflineKeys, Is.Not.Null);
        Assert.That(verificationOptions.OfflineKeysBehavior, Is.EqualTo(OfflineKeysBehavior.NoFallbackToNetwork));
    }

    [Test]
    public void TryCreateClientOptionsForOfflineJwks_WhenOfflineOnlyAndJwksConfigured_SetsSupportedPropertyOrThrowsNotSupported()
    {
        var jwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}";

        var options = new MstTrustOptions
        {
            OfflineOnly = true,
            OfflineTrustedJwksJson = jwksJson,
        };

        // The Azure SDK surface may change; this production code uses reflection against a set of likely names.
        var candidates = new[]
        {
            "TrustedJwksJson",
            "TrustedKeySetJson",
            "TrustedKeysJson",
            "TrustedJwks",
            "TrustedKeySet",
            "TrustedSigningKeys",
            "TrustedKeys",
        };

        var supportedProperty = candidates
            .Select(name => typeof(CodeTransparencyClientOptions).GetProperty(name))
            .FirstOrDefault(p => p is { CanWrite: true } && (p.PropertyType == typeof(string) || p.PropertyType == typeof(BinaryData) || p.PropertyType == typeof(byte[])));

        if (supportedProperty == null)
        {
            var ex = Assert.Throws<NotSupportedException>(() => MstCodeTransparencyOptions.TryCreateClientOptionsForOfflineJwks(options));
            Assert.That(ex!.Message, Does.Contain("Offline trust configuration"));
            return;
        }

        var clientOptions = MstCodeTransparencyOptions.TryCreateClientOptionsForOfflineJwks(options);
        Assert.That(clientOptions, Is.Not.Null);

        var value = supportedProperty.GetValue(clientOptions);
        if (supportedProperty.PropertyType == typeof(string))
        {
            Assert.That(value, Is.EqualTo(jwksJson));
        }
        else if (supportedProperty.PropertyType == typeof(BinaryData))
        {
            Assert.That(((BinaryData)value!).ToString(), Is.EqualTo(jwksJson));
        }
        else if (supportedProperty.PropertyType == typeof(byte[]))
        {
            Assert.That(System.Text.Encoding.UTF8.GetString((byte[])value!), Is.EqualTo(jwksJson));
        }
    }
}
