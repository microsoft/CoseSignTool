// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
public sealed class ScittReceiptIntegrationTests
{
    private static string Describe(CoseSign1ValidationResult result)
    {
        static string Failures(CoseSign1.Validation.Results.ValidationResult r)
        {
            if (r.Failures.Count == 0)
            {
                return string.Empty;
            }

            return string.Join(
                " | ",
                r.Failures.Select(f => string.IsNullOrWhiteSpace(f.ErrorCode) ? f.Message : $"{f.ErrorCode}: {f.Message}"));
        }

        return string.Join(
            "\n",
            $"Resolution: {result.Resolution.Kind} ({Failures(result.Resolution)})",
            $"Trust: {result.Trust.Kind} ({Failures(result.Trust)})",
            $"Signature: {result.Signature.Kind} ({Failures(result.Signature)})",
            $"PostSignaturePolicy: {result.PostSignaturePolicy.Kind} ({Failures(result.PostSignaturePolicy)})",
            $"Overall: {result.Overall.Kind} ({Failures(result.Overall)})");
    }

    private static async Task<string> DescribeMstFactsAsync(CoseSign1Message message, IServiceProvider sp)
    {
        var mstTrustPack = sp.GetServices<ITrustPack>().OfType<MstTrustPack>().SingleOrDefault();
        if (mstTrustPack == null)
        {
            return "MST: no MstTrustPack registered";
        }

        var encoded = message.Encode();
        var messageId = TrustIds.CreateMessageId(encoded);
        var options = new TrustEvaluationOptions();

        var receipts = message.GetMstReceiptBytes();
        if (receipts.Count == 0)
        {
            return "MST: no receipts discovered";
        }

        var lines = new List<string>
        {
            $"MST: receipts discovered = {receipts.Count}",
        };

        for (var i = 0; i < receipts.Count; i++)
        {
            var receiptBytes = receipts[i];
            var subject = TrustSubject.CounterSignature(messageId, receiptBytes);
            var ctx = new TrustFactContext(messageId, subject, options, memoryCache: null, message, services: sp);

            var issuerSet = await mstTrustPack.ProduceAsync(ctx, typeof(MstReceiptIssuerHostFact), CancellationToken.None).ConfigureAwait(false);
            var trustedSet = await mstTrustPack.ProduceAsync(ctx, typeof(MstReceiptTrustedFact), CancellationToken.None).ConfigureAwait(false);

            var issuerFact = (issuerSet as TrustFactSet<MstReceiptIssuerHostFact>)?.Values.SingleOrDefault();
            var trustedFact = (trustedSet as TrustFactSet<MstReceiptTrustedFact>)?.Values.SingleOrDefault();

            var issuerHosts = issuerFact == null
                ? "<none>"
                : issuerFact.Hosts.Count == 0
                    ? "<empty>"
                    : string.Join(", ", issuerFact.Hosts);

            var trusted = trustedFact?.IsTrusted == true;
            var details = string.IsNullOrWhiteSpace(trustedFact?.Details) ? "" : $" ({trustedFact!.Details})";

            lines.Add($"MST[{i}]: issuerHosts={issuerHosts}; trusted={trusted}{details}");
        }

        return string.Join("\n", lines);
    }

    private static string GetTestDataDirectory()
    {
        return Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "Scitt");
    }

    private static string GetMstJwksPath()
    {
        return Path.Combine(TestContext.CurrentContext.TestDirectory, "TestData", "Mst", "esrp-cts-cp.confidential-ledger.azure.com.jwks.json");
    }

    private static IEnumerable<string> EnumerateScittFiles()
    {
        var dir = GetTestDataDirectory();
        if (!Directory.Exists(dir))
        {
            yield break;
        }

        foreach (var file in Directory.EnumerateFiles(dir, "*.scitt", SearchOption.AllDirectories))
        {
            yield return file;
        }
    }

    private static ICoseSign1Validator CreateValidator(IServiceProvider sp)
    {
        // Trust: require at least one MST receipt to be present and trusted.
        // When the receipt is trusted, MST can attest ToBeSigned and staged validation can skip primary signature checks.
        const string expectedIssuerHost = "esrp-cts-cp.confidential-ledger.azure.com";
        var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs
            .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
            .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must be trusted")
            .RequireFact<MstReceiptIssuerHostFact>(
                f => f.Hosts.Any(h => string.Equals(h, expectedIssuerHost, StringComparison.OrdinalIgnoreCase)),
                $"MST receipt issuer host must be {expectedIssuerHost}"));

        var trustPlan = policy.Compile(sp);

        var signingKeyResolvers = sp.GetServices<ISigningKeyResolver>();
        var postSignatureValidators = sp.GetServices<IPostSignatureValidator>();
        var toBeSignedAttestors = sp.GetServices<IToBeSignedAttestor>();

        return new CoseSign1Validator(
            signingKeyResolvers,
            postSignatureValidators,
            toBeSignedAttestors,
            trustPlan,
            options: new CoseSign1ValidationOptions
            {
                AllowToBeSignedAttestationToSkipPrimarySignature = true,
            },
            trustEvaluationOptions: null,
            logger: null);
    }

    [Test]
    public async Task ValidateAsync_WithRealScittFiles_AttestedSkipOccurs_WhenMstReceiptVerifies()
    {
        var files = EnumerateScittFiles().ToArray();
        if (files.Length == 0)
        {
            Assert.Ignore("No .scitt files found under TestData/Scitt.");
        }

        var jwksPath = GetMstJwksPath();
        if (!File.Exists(jwksPath))
        {
            Assert.Ignore($"Missing MST JWKS testdata: {jwksPath}");
        }

        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        // Require a specific ledger/issuer identity and verify using pinned offline keys.
        // This avoids trusting arbitrary receipts and avoids network dependencies.
        var jwksJson = await File.ReadAllTextAsync(jwksPath).ConfigureAwait(false);

        builder.EnableMstSupport(mst => mst
            .UseOfflineTrustedJwksJson(jwksJson));

        using var sp = services.BuildServiceProvider();
        var validator = CreateValidator(sp);

        foreach (var file in files)
        {
            var bytes = await File.ReadAllBytesAsync(file).ConfigureAwait(false);
            var message = CoseMessage.DecodeSign1(bytes);

            var result = await validator.ValidateAsync(message).ConfigureAwait(false);

            var mstFacts = result.Trust.IsSuccess
                ? string.Empty
                : "\n" + await DescribeMstFactsAsync(message, sp).ConfigureAwait(false);

            Assert.That(result.Overall.IsSuccess, Is.True, $"Overall failed for {Path.GetFileName(file)}\n{Describe(result)}{mstFacts}");
            Assert.That(result.Trust.IsSuccess, Is.True, $"Trust failed for {Path.GetFileName(file)}\n{Describe(result)}{mstFacts}");

            // The whole point of the MST receipt ToBeSigned attestation: skip primary key resolution/signature.
            Assert.That(result.Resolution.IsNotApplicable, Is.True, "Expected key resolution to be skipped");
            Assert.That(result.Signature.IsNotApplicable, Is.True, "Expected signature verification to be skipped");
            Assert.That(result.PostSignaturePolicy.IsNotApplicable, Is.True, "Expected post-signature validation to be skipped");

            Assert.That(result.Overall.Metadata, Does.ContainKey("ToBeSignedAttestation.Provider"));
            Assert.That(result.Overall.Metadata["ToBeSignedAttestation.Provider"], Is.EqualTo("MST"));
        }
    }
}
