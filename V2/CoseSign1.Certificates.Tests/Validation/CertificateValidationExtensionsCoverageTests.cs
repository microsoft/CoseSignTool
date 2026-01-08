// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public sealed class CertificateValidationExtensionsCoverageTests
{
    [Test]
    public void ValidateCertificateSignature_AllOverloads_Coverage()
    {
        var builder = new RecordingBuilder();

        builder.ValidateCertificateSignature();
        builder.ValidateCertificateSignature(new byte[] { 1, 2, 3 });
        builder.ValidateCertificateSignature(new ReadOnlyMemory<byte>(new byte[] { 4, 5, 6 }));

        Assert.That(builder.Calls, Does.Contain("AddValidator"));
    }

    [Test]
    public void CertificateValidationBuilder_NullArguments_Throw()
    {
        Assert.That(() => new CertificateValidationBuilder((byte[])null!), Throws.ArgumentNullException);

        var builder = new CertificateValidationBuilder();
        Assert.That(() => builder.Matches(null!), Throws.ArgumentNullException);
        Assert.That(() => builder.ValidateChain((X509Certificate2Collection)null!), Throws.ArgumentNullException);
        Assert.That(() => builder.ValidateChain((ICertificateChainBuilder)null!), Throws.ArgumentNullException);

        Assert.That(() => SignatureValidationExtensions.ValidateCertificateSignature(null!), Throws.ArgumentNullException);
        Assert.That(() => SignatureValidationExtensions.ValidateCertificateSignature(null!, new byte[] { 1 }), Throws.ArgumentNullException);
        Assert.That(() => SignatureValidationExtensions.ValidateCertificateSignature(null!, new ReadOnlyMemory<byte>(new byte[] { 1 })), Throws.ArgumentNullException);
    }

    [Test]
    public void CertificateValidationBuilder_ConstructorsAndBuild_Coverage()
    {
        var builder = new RecordingBuilder();

        builder.AddValidator(new CertificateValidationBuilder()
            .AllowUnprotectedHeaders()
            .NotExpired(DateTime.UtcNow)
            .HasCommonName("Test")
            .IsIssuedBy("Issuer")
            .HasKeyUsage(X509KeyUsageFlags.DigitalSignature)
            .HasEnhancedKeyUsage("1.2.3")
            .ValidateChain()
            .Build());

        builder.AddValidator(new CertificateValidationBuilder(new byte[] { 1, 2, 3 })
            .AllowUnprotectedHeaders()
            .NotExpired()
            .Matches(_ => true)
            .Build());

        builder.AddValidator(new CertificateValidationBuilder(new ReadOnlyMemory<byte>(new byte[] { 4, 5, 6 }))
            .AllowUnprotectedHeaders()
            .NotExpired()
            .ValidateChain(new X509Certificate2Collection(), trustUserRoots: false, revocationMode: X509RevocationMode.Offline)
            .ValidateChain(new NoopChainBuilder())
            .Build());

        builder.AddValidator(new CertificateValidationBuilder()
            .AllowUnprotectedHeaders()
            .NotExpired()
            .HasCommonName("Test")
            .HasEnhancedKeyUsage(new Oid("1.2.3"))
            .Matches(_ => true)
            .Build());

        Assert.That(builder.Calls, Is.Not.Empty);
        Assert.That(builder.Calls, Does.Contain("AddValidator"));
    }

    private sealed class NoopChainBuilder : ICertificateChainBuilder
    {
        public IReadOnlyCollection<X509Certificate2> ChainElements { get; private set; } = Array.Empty<X509Certificate2>();

        public X509ChainPolicy ChainPolicy { get; set; } = new();

        public X509ChainStatus[] ChainStatus { get; private set; } = Array.Empty<X509ChainStatus>();

        public bool Build(X509Certificate2 certificate)
        {
            ChainElements = new[] { certificate };
            ChainStatus = Array.Empty<X509ChainStatus>();
            return true;
        }
    }

    private sealed class RecordingBuilder : ICoseSign1ValidationBuilder
    {
        public ValidationBuilderContext Context { get; } = new();

        public System.Collections.Generic.List<string> Calls { get; } = new();

        public ICoseSign1ValidationBuilder AddValidator(IValidator validator)
        {
            Calls.Add("AddValidator");
            return this;
        }

        public ICoseSign1ValidationBuilder RequireTrust(TrustPolicy policy)
        {
            Calls.Add("RequireTrust");
            return this;
        }

        public ICoseSign1ValidationBuilder AllowAllTrust(string? reason = null)
        {
            Calls.Add("AllowAllTrust");
            return this;
        }

        public ICoseSign1ValidationBuilder DenyAllTrust(string? reason = null)
        {
            Calls.Add("DenyAllTrust");
            return this;
        }

        public ICoseSign1Validator Build()
        {
            throw new NotSupportedException("Not needed for coverage tests");
        }
    }
}
