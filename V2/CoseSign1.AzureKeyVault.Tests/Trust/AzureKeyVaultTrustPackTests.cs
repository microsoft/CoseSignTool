// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Trust;

using System.Text;
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
public class AzureKeyVaultTrustPackTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("akv-trust-pack test payload");
    private static readonly CoseHeaderLabel KidLabel = new(4);

    private static TrustFactContext CreateMessageContext(CoseSign1Message? message)
    {
        if (message == null)
        {
            // We still need a stable message id to construct the context. Use any deterministic ID.
            // The trust pack under test validates Message == null and returns Missing.
            var id = TrustIds.CreateMessageId(Encoding.UTF8.GetBytes("missing-message"));
            var missingSubject = TrustSubject.Message(id);
            return new TrustFactContext(id, missingSubject, new TrustEvaluationOptions(), memoryCache: null, message: null);
        }

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.Message(messageId);
        return new TrustFactContext(messageId, subject, new TrustEvaluationOptions(), memoryCache: null, message: message);
    }

    private static CoseSign1Message CreateMessage(bool includeKid, string? kidValue = null, bool kidInProtectedHeaders = true)
    {
        using RSA rsa = RSA.Create(2048);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        if (includeKid)
        {
            var bytes = Encoding.UTF8.GetBytes(kidValue ?? string.Empty);
            if (kidInProtectedHeaders)
            {
                protectedHeaders.Add(KidLabel, bytes);
            }
            else
            {
                unprotectedHeaders.Add(KidLabel, bytes);
            }
        }

        CoseSigner coseSigner = new(
            rsa,
            RSASignaturePadding.Pkcs1,
            HashAlgorithmName.SHA256,
            protectedHeaders,
            unprotectedHeaders);

        byte[] coseBytes = CoseSign1Message.SignEmbedded(TestPayload, coseSigner);
        return CoseMessage.DecodeSign1(coseBytes);
    }

    [Test]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultTrustPack(null!));
    }

    [Test]
    public void ProduceAsync_WhenContextNull_ThrowsArgumentNullException()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        Assert.That(() => trustPack.ProduceAsync(null!, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public void ProduceAsync_WhenFactTypeNull_ThrowsArgumentNullException()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        var message = CreateMessage(includeKid: false);
        var context = CreateMessageContext(message);

        Assert.That(() => trustPack.ProduceAsync(context, null!, CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public async Task ProduceAsync_WhenMessageMissing_ReturnsMissingFacts()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        var context = CreateMessageContext(message: null);

        var detected = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);
        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(detected.IsMissing, Is.True);
        Assert.That(allowed.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceAsync_WhenKidMissing_ReturnsMissingFacts()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        var message = CreateMessage(includeKid: false);
        var context = CreateMessageContext(message);

        var detected = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);
        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(detected.IsMissing, Is.True);
        Assert.That(allowed.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceAsync_WhenKidHeaderPresentButEmpty_TreatsAsMissing()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());

        var messageProtected = CreateMessage(includeKid: true, kidValue: string.Empty, kidInProtectedHeaders: true);
        var contextProtected = CreateMessageContext(messageProtected);
        var detectedProtected = await trustPack.ProduceAsync(contextProtected, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);
        Assert.That(detectedProtected.IsMissing, Is.True);

        var messageUnprotected = CreateMessage(includeKid: true, kidValue: string.Empty, kidInProtectedHeaders: false);
        var contextUnprotected = CreateMessageContext(messageUnprotected);
        var allowedUnprotected = await trustPack.ProduceAsync(contextUnprotected, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);
        Assert.That(allowedUnprotected.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceAsync_DetectsAzureKeyVaultKid()
    {
        const string akvKid = "https://myvault.vault.azure.net/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        var message = CreateMessage(includeKid: true, kidValue: akvKid, kidInProtectedHeaders: true);
        var context = CreateMessageContext(message);

        var detected = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);

        Assert.That(detected.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidDetectedFact>)detected;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].IsAzureKeyVaultKey, Is.True);
    }

    [Test]
    public async Task ProduceAsync_RequiresAzureKeyVaultKid_WhenConfigured()
    {
        const string nonAkvKid = "https://example.com/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions { RequireAzureKeyVaultKid = true, AllowedKidPatterns = new[] { "*" } });
        var message = CreateMessage(includeKid: true, kidValue: nonAkvKid, kidInProtectedHeaders: false);
        var context = CreateMessageContext(message);

        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(allowed.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowed;
        Assert.That(typed.Values[0].IsAllowed, Is.False);
    }

    [Test]
    public async Task ProduceAsync_AllowsKid_WhenGlobPatternMatches()
    {
        const string akvKid = "https://myvault.vault.azure.net/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions
        {
            RequireAzureKeyVaultKid = true,
            AllowedKidPatterns = new[] { "https://myvault.vault.azure.net/keys/*" }
        });

        var message = CreateMessage(includeKid: true, kidValue: akvKid);
        var context = CreateMessageContext(message);

        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(allowed.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowed;
        Assert.That(typed.Values[0].IsAllowed, Is.True);
    }

    [Test]
    public async Task ProduceAsync_AllowsKid_WhenRegexPatternMatches()
    {
        const string akvKid = "https://myvault.vault.azure.net/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions
        {
            AllowedKidPatterns = new[] { "regex:https://.*\\.vault\\.azure\\.net/keys/.*" }
        });

        var message = CreateMessage(includeKid: true, kidValue: akvKid);
        var context = CreateMessageContext(message);

        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(allowed.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowed;
        Assert.That(typed.Values[0].IsAllowed, Is.True);
    }

    [Test]
    public async Task ProduceAsync_WhenNoAllowedPatternsConfigured_ReturnsNotAllowed_WithDetails()
    {
        const string akvKid = "https://myvault.vault.azure.net/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions
        {
            AllowedKidPatterns = Array.Empty<string>()
        });

        var message = CreateMessage(includeKid: true, kidValue: akvKid);
        var context = CreateMessageContext(message);

        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(allowed.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowed;
        Assert.That(typed.Values[0].IsAllowed, Is.False);
        Assert.That(typed.Values[0].Details, Is.EqualTo("NoAllowedPatterns"));
    }

    [Test]
    public async Task ProduceAsync_WhenAllowedPatternsDoNotMatch_ReturnsNotAllowed_WithDetails()
    {
        const string akvKid = "https://myvault.vault.azure.net/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions
        {
            AllowedKidPatterns = new[] { "https://other.vault.azure.net/keys/*" }
        });

        var message = CreateMessage(includeKid: true, kidValue: akvKid);
        var context = CreateMessageContext(message);

        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(allowed.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowed;
        Assert.That(typed.Values[0].IsAllowed, Is.False);
        Assert.That(typed.Values[0].Details, Is.EqualTo("NoPatternMatch"));
    }

    [Test]
    public async Task ProduceAsync_WhenAllowedPatternsAllWhitespace_ReturnsNotAllowed_WithDetails()
    {
        const string akvKid = "https://myvault.vault.azure.net/keys/mykey/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions
        {
            AllowedKidPatterns = new[] { " ", "\t", "\r\n" }
        });

        var message = CreateMessage(includeKid: true, kidValue: akvKid);
        var context = CreateMessageContext(message);

        var allowed = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidAllowedFact), CancellationToken.None);

        Assert.That(allowed.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidAllowedFact>)allowed;
        Assert.That(typed.Values[0].IsAllowed, Is.False);
        Assert.That(typed.Values[0].Details, Is.EqualTo("NoAllowedPatterns"));
    }

    [Test]
    public async Task ProduceAsync_WhenFactTypeUnsupported_ThrowsNotSupportedException()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions { AllowedKidPatterns = new[] { "*" } });
        var message = CreateMessage(includeKid: true, kidValue: "https://myvault.vault.azure.net/keys/mykey/123");
        var context = CreateMessageContext(message);

        Assert.That(async () => await trustPack.ProduceAsync(context, typeof(string), CancellationToken.None), Throws.InstanceOf<NotSupportedException>());
    }

    [Test]
    public async Task ProduceAsync_WithNonUriKid_DetectsNotAzureKeyVault()
    {
        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        var message = CreateMessage(includeKid: true, kidValue: "not a uri");
        var context = CreateMessageContext(message);

        var detected = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);

        Assert.That(detected.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidDetectedFact>)detected;
        Assert.That(typed.Values[0].IsAzureKeyVaultKey, Is.False);
    }

    [Test]
    public async Task ProduceAsync_WithVaultHostButNonKeysPath_DetectsNotAzureKeyVault()
    {
        const string notKeyId = "https://myvault.vault.azure.net/secrets/s/123";

        var trustPack = new AzureKeyVaultTrustPack(new AzureKeyVaultTrustOptions());
        var message = CreateMessage(includeKid: true, kidValue: notKeyId);
        var context = CreateMessageContext(message);

        var detected = await trustPack.ProduceAsync(context, typeof(AzureKeyVaultKidDetectedFact), CancellationToken.None);

        Assert.That(detected.IsMissing, Is.False);
        var typed = (ITrustFactSet<AzureKeyVaultKidDetectedFact>)detected;
        Assert.That(typed.Values[0].IsAzureKeyVaultKey, Is.False);
    }

    [Test]
    public void EnableAzureKeyVaultSupport_RegistersOptionsAndTrustPack()
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        _ = builder.EnableAzureKeyVaultSupport(b => b.RequireAzureKeyVaultKid().AllowKidPatterns(new[] { "*" }).OfflineOnly());

        Assert.That(services.Any(sd => sd.ServiceType == typeof(AzureKeyVaultTrustOptions)), Is.True);
        Assert.That(services.Any(sd => sd.ServiceType == typeof(ITrustPack) && sd.ImplementationType == typeof(AzureKeyVaultTrustPack)), Is.True);
    }
}
