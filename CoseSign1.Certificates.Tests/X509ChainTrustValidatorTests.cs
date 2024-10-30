// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Test class for <see cref="X509ChainTrustValidator"/>
/// </summary>
public class X509ChainTrustValidatorTests
{
    private static readonly X509Certificate2Collection DefaultTestChain = TestCertificateUtils.CreateTestChain();
    private static readonly List<X509Certificate2> DefaultRoots = [.. DefaultTestChain];
    private static readonly byte[] DefaultTestArray = [1, 2, 3, 4];

    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }

    private static IEnumerable<Tuple<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>> X509ChainTrustValidatorCtorsTestData()
    {
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        X509Certificate2Collection certChain = TestCertificateUtils.CreateTestChain();

        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                revocationMode: X509RevocationMode.NoCheck),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                revocationMode: X509RevocationMode.NoCheck,
                allowUnprotected: true,
                allowUntrusted: true),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeTrue();
                trustValidator.AllowUnprotected.Should().BeTrue();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                revocationMode: X509RevocationMode.NoCheck,
                allowUnprotected: false,
                allowUntrusted: true),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeTrue();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                revocationMode: X509RevocationMode.NoCheck,
                allowUnprotected: true,
                allowUntrusted: false),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeTrue();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(chainBuilder: mockBuilder.Object),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().Be(mockBuilder.Object);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(chainBuilder: mockBuilder.Object, allowUnprotected: true, allowUntrusted: true),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeTrue();
                trustValidator.AllowUnprotected.Should().BeTrue();
                trustValidator.ChainBuilder.Should().Be(mockBuilder.Object);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(chainBuilder: mockBuilder.Object, allowUnprotected: false, allowUntrusted: true),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeTrue();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().Be(mockBuilder.Object);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(chainBuilder: mockBuilder.Object, allowUnprotected: false, allowUntrusted: false),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().Be(mockBuilder.Object);
                trustValidator.Roots.Should().BeNull();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                roots: [.. certChain]),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.Online);
                trustValidator.Roots.Should().NotBeNull();
                trustValidator.Roots?.Count.Should().Be(certChain.Count);
                trustValidator.Roots?.SequenceEqual(certChain).Should().BeTrue();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                roots: [.. certChain],
                revocationMode: X509RevocationMode.NoCheck),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().NotBeNull();
                trustValidator.Roots?.Count.Should().Be(certChain.Count);
                trustValidator.Roots?.SequenceEqual(certChain).Should().BeTrue();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                roots: [.. certChain],
                revocationMode: X509RevocationMode.NoCheck,
                allowUnprotected: true,
                allowUntrusted: true),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeTrue();
                trustValidator.AllowUnprotected.Should().BeTrue();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().NotBeNull();
                trustValidator.Roots?.Count.Should().Be(certChain.Count);
                trustValidator.Roots?.SequenceEqual(certChain).Should().BeTrue();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                roots: [.. certChain],
                revocationMode: X509RevocationMode.NoCheck,
                allowUnprotected: false,
                allowUntrusted: true),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeTrue();
                trustValidator.AllowUnprotected.Should().BeFalse();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().NotBeNull();
                trustValidator.Roots?.Count.Should().Be(certChain.Count);
                trustValidator.Roots?.SequenceEqual(certChain).Should().BeTrue();
            });
        yield return Tuple.Create<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>>(
            () => new X509ChainTrustValidator(
                roots: [.. certChain],
                revocationMode: X509RevocationMode.NoCheck,
                allowUnprotected: true,
                allowUntrusted: false),
            (trustValidator) =>
            {
                trustValidator.AllowUntrusted.Should().BeFalse();
                trustValidator.AllowUnprotected.Should().BeTrue();
                trustValidator.ChainBuilder.Should().BeOfType<X509ChainBuilder>();
                trustValidator.ChainBuilder.ChainPolicy.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
                trustValidator.Roots.Should().NotBeNull();
                trustValidator.Roots?.Count.Should().Be(certChain.Count);
                trustValidator.Roots?.SequenceEqual(certChain).Should().BeTrue();
            });
    }

    /// <summary>
    /// Run through some basic validator tests.
    /// </summary>
    [Test,
     TestCaseSource(nameof(X509ChainTrustValidatorCtorsTestData))]
    public void X509ChainTrustValidatorCtors(Tuple<Func<X509ChainTrustValidator>, Action<X509ChainTrustValidator>> inputCase)
    {
        X509ChainTrustValidator? testItem = null;
#pragma warning disable CS8604 // Deliberately testing a null handler
        Assert.DoesNotThrow(() => testItem = inputCase.Item1());
        Assert.DoesNotThrow(() => inputCase.Item2(testItem));
#pragma warning restore CS8604
    }



    // Prove that validation succeeds when CertificateChain.Build succeeds.
    [Test]
    public void X509TrustValidatorBasicSuccess()
    {
        // Build a COSE embed-signed file with a cert chain
        CoseSign1Message message = CreateCoseSign1MessageWithChainedCert();

        // Mock the ChainBuilder to always return success
        Mock<ICertificateChainBuilder> mockBuilder = new();
        mockBuilder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockBuilder.Setup(x => x.ChainElements).Returns([.. DefaultTestChain]);
        mockBuilder.Setup(x => x.ChainPolicy).Returns(new X509ChainPolicy());

        // Validate
        X509ChainTrustValidator Validator = new(mockBuilder.Object);
        Validator.TryValidate(message, out List<CoseSign1ValidationResult> results).Should().BeTrue();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeTrue();
        results[0].ResultMessage.Should().Be("Certificate was Trusted.");
        results[0].Includes.Should().BeNull();
    }

    // Prove that validation succeeds when the cert chains to a user-supplied root unless TrustUserRoots
    // is turned off.
    [Test]
    public void X509TrustValidatorValidUserRoot()
    {
        // Build a COSE embed-signed file with a cert chain
        CoseSign1Message message = CreateCoseSign1MessageWithChainedCert();

        // Validate with TrustUserRoots ON (default state)
        X509ChainTrustValidator Validator = new(DefaultRoots, X509RevocationMode.NoCheck);
        Validator.TryValidate(message, out List<CoseSign1ValidationResult> results)
            .Should().BeTrue(string.Join("\n", results.Select(v => v.ResultMessage)));

        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeTrue();
        results[0].ResultMessage.Should().Be("Certificate was Trusted.");
        results[0].Includes.Should().BeNull();

        // Validate with TrustUserRoots OFF
        Validator.TrustUserRoots = false;            
        Validator.TryValidate(message, out results).Should().BeFalse();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeFalse();
        results[0].Includes.Should().NotBeNull();
        results[0].Includes?.Count.Should().Be(1);
        X509ChainStatus? status = results[0].Includes?.Cast<X509ChainStatus>().FirstOrDefault();
        status.Value.Status.Should().Be(X509ChainStatusFlags.UntrustedRoot);
    }

    // Prove that validation passes with an untrusted root only when AllowUntrusted is ON
    [Test]
    public void X509TrustValidatorInvalidUserRoot()
    {
        // Build a COSE embed-signed file with a cert chain
        CoseSign1Message message = CreateCoseSign1MessageWithChainedCert();

        // Validate with TrustUserRoots OFF and AllowUntrusted ON
        X509ChainTrustValidator Validator = new(DefaultRoots, X509RevocationMode.NoCheck)
        {
            TrustUserRoots = false,
            AllowUntrusted = true
        };
        Validator.TryValidate(message, out List<CoseSign1ValidationResult> results).Should().BeTrue();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeTrue();
        results[0].ResultMessage.Should().Be("Certificate was allowed because AllowUntrusted was specified.");
        results[0].Includes.Should().BeNull();

        // Validate with AllowUntrusted OFF covered by X509TrustValidatorValidUserRoot test
    }

    // Prove that when the roots are not present validation fails, even with both TrustUserRoots and AllowUntrusted ON
    [Test]
    public void X509TrustValidatorNoRoot()
    {
        // Build a COSE embed-signed file with a cert chain
        CoseSign1Message message = CreateCoseSign1MessageWithChainedCert();

        // Validate with TrustUserRoots and AllowUntrusted ON but no roots provided
        X509ChainTrustValidator Validator = new(X509RevocationMode.Offline)
        {
            TrustUserRoots = false,
            AllowUntrusted = false
        };
        Validator.TryValidate(message, out List<CoseSign1ValidationResult> results).Should().BeFalse();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeFalse();
        results[0].Includes.Should().NotBeNull();
        results[0].Includes?.Count.Should().Be(3);
        List<X509ChainStatus> status = [.. results[0].Includes?.Cast<X509ChainStatus>()];

        // When root is distrusted with a revocation checks turned on, the chain status will include the following
        status.Any(s => s.Status == X509ChainStatusFlags.UntrustedRoot).Should().BeTrue();
        status.Any(s => s.Status == X509ChainStatusFlags.OfflineRevocation).Should().BeTrue();
        status.Any(s => s.Status == X509ChainStatusFlags.RevocationStatusUnknown).Should().BeTrue();
    }

    // Prove that an untrusted, self-signed cert passes only when the same cert is passed as a root or AllowUntrusted is ON
    [Test]
    public void X509TrustValidatorSelfSigned()
    {
        // Build a COSE embed-signed file with a self-signed certificate
        var cert = TestCertificateUtils.CreateCertificate();
        CoseSign1MessageFactory factory = new();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(null, cert);
        var message = factory.CreateCoseSign1Message(DefaultTestArray, keyProvider, embedPayload: true);

        // Validate with certificate provided as root
        var roots = new List<X509Certificate2>() { cert };
        X509ChainTrustValidator Validator = new(roots, X509RevocationMode.NoCheck);
        Validator.TryValidate(message, out List<CoseSign1ValidationResult> results).Should().BeTrue();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeTrue();
        results[0].ResultMessage.Should().Be("Certificate was Trusted.");
        results[0].Includes.Should().BeNull();

        // Validate with AllowUntrusted ON but no roots provided
        Validator = new(X509RevocationMode.NoCheck, false, true);
        Validator.TryValidate(message, out results).Should().BeTrue();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeTrue();
        results[0].ResultMessage.Should().Be("Certificate was allowed because AllowUntrusted was specified.");
        results[0].Includes.Should().BeNull();

        // Validate with AllowUntrusted OFF and no roots provided
        Validator = new(X509RevocationMode.NoCheck);
        Validator.TryValidate(message, out results).Should().BeFalse();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeFalse();
        results[0].Includes.Should().NotBeNull();
        results[0].Includes?.Count.Should().Be(1);
        X509ChainStatus? status = results[0].Includes?.Cast<X509ChainStatus>().FirstOrDefault();
        status.Value.Status.Should().Be(X509ChainStatusFlags.UntrustedRoot);

        // Validate with AllowUntrusted AND AllowOutdated and an expired certificate
        var expiredCert = TestCertificateUtils.CreateCertificate("X509TrustValidatorSelfSigned-Expired", null, false, null, TimeSpan.FromSeconds(1));
        Thread.Sleep(1000);
        X509Certificate2CoseSigningKeyProvider keyProviderWithExpiredCert = new(null, expiredCert);
        var messageExpired = factory.CreateCoseSign1Message(DefaultTestArray, keyProviderWithExpiredCert, embedPayload: true);
        Validator = new(X509RevocationMode.NoCheck, false, allowUntrusted: true, allowOutdated: true);
        Validator.TryValidate(messageExpired, out List<CoseSign1ValidationResult> resultsExpired).Should().BeTrue();
        resultsExpired.Count.Should().Be(1);
        resultsExpired[0].PassedValidation.Should().BeTrue();
        resultsExpired[0].ResultMessage.Should().Contain("AllowOutdated and AllowUntrusted");
        resultsExpired[0].Includes.Should().BeNull();

        // Validate with AllowOutdated OFF and an expired certificate
        Validator = new(X509RevocationMode.NoCheck, false, allowUntrusted: true, allowOutdated: false);
        Validator.TryValidate(messageExpired, out resultsExpired).Should().BeFalse();
        resultsExpired.Count.Should().Be(1);
        resultsExpired[0].PassedValidation.Should().BeFalse();
        resultsExpired[0].Includes.Should().NotBeNull();
        resultsExpired[0].Includes?.Count.Should().Be(2);
        status = resultsExpired[0].Includes?.Cast<X509ChainStatus>()
            .FirstOrDefault(s => s.Status == X509ChainStatusFlags.NotTimeValid);
        status.Should().NotBeNull();

        // Validate with AllowOutdated ON and an expired certificate with a lifetime EKU
        var expiredCertWithLifetimeEku = TestCertificateUtils.CreateCertificate("X509TrustValidatorSelfSigned-Expired",
            null, false, null, TimeSpan.FromSeconds(1), addLifetimeEku: true);
        Thread.Sleep(1000);
        X509Certificate2CoseSigningKeyProvider keyProviderLifetimeEku = new(null, expiredCertWithLifetimeEku);
        var messageLifetimeEku = factory.CreateCoseSign1Message(DefaultTestArray, keyProviderLifetimeEku, embedPayload: true);
        Validator = new(X509RevocationMode.NoCheck, false, allowUntrusted: true, allowOutdated: true);
        Validator.TryValidate(messageLifetimeEku, out List<CoseSign1ValidationResult> resultsLifetimeEku).Should().BeFalse();
        resultsLifetimeEku.Count.Should().Be(1);
        resultsLifetimeEku[0].PassedValidation.Should().BeFalse();
        resultsLifetimeEku[0].Includes.Should().NotBeNull();
        resultsLifetimeEku[0].Includes?.Count.Should().Be(2);
        status = resultsExpired[0].Includes?.Cast<X509ChainStatus>()
            .FirstOrDefault(s => s.Status == X509ChainStatusFlags.NotTimeValid);
        status.Should().NotBeNull();
    }

    // Check outputs for miscellaneous error cases.
    [Test]
    public void X509TrustValidatorBasicFailureCases()
    {
        // Mismatched roots case //
        CoseSign1Message message = CreateCoseSign1MessageWithChainedCert();
        List<X509Certificate2> mismatchedRoots = [.. TestCertificateUtils.CreateTestChain("Mismatched root set")];
        X509ChainTrustValidator Validator = new(mismatchedRoots, X509RevocationMode.NoCheck);
        Validator.TryValidate(message, out List<CoseSign1ValidationResult> results).Should().BeFalse();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeFalse();
        results[0].Includes.Should().NotBeNull();
        results[0].Includes?.Count.Should().Be(1);
        X509ChainStatus? status = results[0].Includes?.Cast<X509ChainStatus>().FirstOrDefault();
        status.Value.Status.Should().Be(X509ChainStatusFlags.UntrustedRoot);

        // Revoked cert case //
        Mock<ICertificateChainBuilder> builder = new();
        builder.Setup(x => x.Build(It.IsAny<X509Certificate2>())).Returns(false);
        builder.Setup(x => x.ChainElements).Returns([.. DefaultTestChain]);
        builder.Setup(x => x.ChainStatus).Returns([new X509ChainStatus() { Status = X509ChainStatusFlags.Revoked }]);
        builder.Setup(x => x.ChainPolicy).Returns(new X509ChainPolicy());
        Validator.ChainBuilder = builder.Object;
        Validator.TryValidate(message, out results).Should().BeFalse();
        results.Count.Should().Be(1);
        results[0].PassedValidation.Should().BeFalse();
        results[0].Includes.Should().NotBeNull();
        results[0].Includes?.Count.Should().Be(1);
        status = results[0].Includes?.Cast<X509ChainStatus>().FirstOrDefault();
        status.Value.Status.Should().Be(X509ChainStatusFlags.Revoked);
    }

    /// <summary>
    /// validates when certificate provided is null
    /// </summary>
    [Test]
    public void X509TrustValidatorValidatesNullCertificate()
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("testPayload!");
        X509Certificate2 testCertRsa = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap();
        var unProtectedHeaders = new CoseHeaderMap();
        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns(protectedHeaders);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns(unProtectedHeaders);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(testCertRsa.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        CoseSign1MessageBuilder coseSign1MessageBuilder = new(mockedSignerKeyProvider.Object);
        CoseSign1Message message = coseSign1MessageBuilder.SetPayloadBytes(testPayload).Build() ?? throw new ArgumentNullException();

        X509ChainTrustValidator testChainTrustValidator = new(mockBuilder.Object);
        testChainTrustValidator.TryValidate(message, out List<CoseSign1ValidationResult>? validationResults).Should().BeFalse();
        validationResults[0].ResultMessage.Should().NotBeNull();
        validationResults.Count.Should().Be(1);
        validationResults[0].PassedValidation.Should().BeFalse();
    }

    /// <summary>
    /// Validates the retry logic when revocation status is unknown
    /// </summary>
    [Test]
    public void ValidateCertificateRetriesOnRevocationStatusUnknown()
    {
        // Arrange
        X509ChainStatus[] revUnknown = [new X509ChainStatus() { Status = X509ChainStatusFlags.RevocationStatusUnknown }];
        X509ChainPolicy policy = new();

        Mock<ICertificateChainBuilder> mockBuilder = new(MockBehavior.Strict);
        mockBuilder.Setup(x => x.ChainStatus).Returns(revUnknown);
        mockBuilder.Setup(x => x.ChainPolicy).Returns(policy);
        mockBuilder.SetupSequence(x => x.Build(It.IsAny<X509Certificate2>()))
            .Returns(false)
            .Returns(false)
            .Returns(true);

        // Act
        X509ChainTrustValidator validator = new(mockBuilder.Object);

        // Assert
        validator.TryValidate(CreateCoseSign1MessageWithChainedCert(), out List<CoseSign1ValidationResult> results).Should().BeTrue();
        mockBuilder.Verify(b => b.Build(It.IsAny<X509Certificate2>()), Times.Exactly(3));
    }

    private static CoseSign1Message CreateCoseSign1MessageWithChainedCert()
    {
        CoseSign1MessageFactory factory = new();
        X509Certificate2CoseSigningKeyProvider keyProvider = new(null, DefaultTestChain.Last(), [.. DefaultTestChain]);
        return factory.CreateCoseSign1Message(DefaultTestArray, keyProvider, embedPayload: true);
    }
}
