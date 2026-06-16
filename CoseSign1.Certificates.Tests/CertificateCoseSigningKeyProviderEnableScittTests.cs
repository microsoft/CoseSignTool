// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Tests for EnableScittCompliance functionality in <see cref="CertificateCoseSigningKeyProvider"/>
/// </summary>
public class CertificateCoseSigningKeyProviderEnableScittTests
{
    /// <summary>
    /// Tests that EnableScittCompliance defaults to true
    /// </summary>
    [Test]
    public void TestEnableScittCompliance_DefaultsToTrue()
    {
        // Arrange & Act
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        X509Certificate2CoseSigningKeyProvider provider = new(chainBuilder, cert);

        // Assert
        provider.EnableScittCompliance.Should().BeTrue("EnableScittCompliance should default to true");
    }

    /// <summary>
    /// Tests that when EnableScittCompliance is false, no default CWT claims are added
    /// </summary>
    [Test]
    public void TestGetProtectedHeaders_WithScittDisabled_DoesNotIncludeDefaultCWTClaims()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        X509Certificate2CoseSigningKeyProvider provider = new(chainBuilder, cert, enableScittCompliance: false);

        // Act
        CoseHeaderMap headers = provider.GetProtectedHeaders();

        // Assert
        headers.Should().NotBeNull();
        headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims).Should().BeFalse(
            "GetProtectedHeaders should NOT add default CWT claims when EnableScittCompliance is false");
        
        bool hasClaims = headers.TryGetCwtClaims(out CwtClaims? claims);
        hasClaims.Should().BeFalse("No CWT claims should be present when EnableScittCompliance is false");
        claims.Should().BeNull();
    }

    /// <summary>
    /// Tests that EnableScittCompliance can be set after construction
    /// </summary>
    [Test]
    public void TestEnableScittCompliance_CanBeSetAfterConstruction()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        X509Certificate2CoseSigningKeyProvider provider = new(chainBuilder, cert);

        // Act - Disable SCITT compliance after construction
        provider.EnableScittCompliance = false;
        CoseHeaderMap headers = provider.GetProtectedHeaders();

        // Assert
        headers.Should().NotBeNull();
        headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims).Should().BeFalse(
            "No default CWT claims should be added when EnableScittCompliance is set to false");
    }

    /// <summary>
    /// Tests that enabling SCITT compliance after disabling it works correctly
    /// </summary>
    [Test]
    public void TestEnableScittCompliance_CanBeToggledMultipleTimes()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        X509Certificate2CoseSigningKeyProvider provider = new(chainBuilder, cert, enableScittCompliance: false);

        // Act & Assert - Initially disabled
        provider.EnableScittCompliance.Should().BeFalse();
        CoseHeaderMap headers1 = provider.GetProtectedHeaders();
        headers1.ContainsKey(CWTClaimsHeaderLabels.CWTClaims).Should().BeFalse();

        // Re-enable SCITT compliance
        provider.EnableScittCompliance = true;
        CoseHeaderMap headers2 = provider.GetProtectedHeaders();
        headers2.ContainsKey(CWTClaimsHeaderLabels.CWTClaims).Should().BeTrue(
            "CWT claims should be added when EnableScittCompliance is re-enabled");
    }

    /// <summary>
    /// Tests that when SCITT compliance is enabled, default CWT claims are included
    /// </summary>
    [Test]
    public void TestGetProtectedHeaders_WithScittEnabled_IncludesDefaultCWTClaims()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        X509Certificate2CoseSigningKeyProvider provider = new(chainBuilder, cert, enableScittCompliance: true);

        // Act
        CoseHeaderMap headers = provider.GetProtectedHeaders();

        // Assert
        headers.Should().NotBeNull();
        headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims).Should().BeTrue(
            "GetProtectedHeaders should add default CWT claims when EnableScittCompliance is true");
        
        bool hasClaims = headers.TryGetCwtClaims(out CwtClaims? claims);
        hasClaims.Should().BeTrue();
        claims.Should().NotBeNull();
        claims!.Issuer.Should().NotBeNull();
        claims.Subject.Should().Be(CwtClaims.DefaultSubject);
    }

    /// <summary>
    /// Verifies that <see cref="CertificateCoseSigningKeyProvider"/> implements the shared
    /// <see cref="ISupportsScittCompliance"/> capability interface from
    /// <c>CoseSign1.Abstractions</c>. This is the cross-AssemblyLoadContext contract that lets
    /// the host toggle SCITT compliance on plugin-returned providers without referencing the
    /// concrete provider type — keeping <c>CoseSign1.Certificates</c> plugin-local.
    /// </summary>
    [Test]
    public void TestImplementsISupportsScittCompliance_ContractDefinedInAbstractions()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider provider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, cert);

        // Act — host pattern: probe via shared capability interface, never via concrete type.
        bool implementsScittCapability = provider is ISupportsScittCompliance;

        // Assert
        implementsScittCapability.Should().BeTrue(
            "CertificateCoseSigningKeyProvider must expose the shared ISupportsScittCompliance capability so the host can toggle SCITT compliance without depending on the concrete type");

        // The capability interface MUST live in CoseSign1.Abstractions so it can be host-shared
        // across plugin AssemblyLoadContext boundaries. Verifying this stops accidental moves
        // into a plugin-local assembly.
        typeof(ISupportsScittCompliance).Assembly.GetName().Name.Should().Be(
            "CoseSign1.Abstractions",
            "ISupportsScittCompliance must remain in the host-shared CoseSign1.Abstractions assembly to preserve cross-ALC type identity");
    }

    /// <summary>
    /// Verifies the round-trip: setting EnableScittCompliance through the
    /// <see cref="ISupportsScittCompliance"/> interface flows through to the underlying provider's
    /// behavior (matching the <c>SignCommand</c> downcast pattern).
    /// </summary>
    [Test]
    public void TestISupportsScittCompliance_RoundTripsThroughInterface()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder chainBuilder = new TestChainBuilder();
        ICoseSigningKeyProvider provider = new X509Certificate2CoseSigningKeyProvider(chainBuilder, cert);

        // Act — exact mirror of SignCommand's host-side pattern after the Phase 3 refactor.
        if (provider is ISupportsScittCompliance scittProvider)
        {
            scittProvider.EnableScittCompliance = false;
        }

        // Assert — concrete property reflects the interface-driven change.
        ((CertificateCoseSigningKeyProvider)provider).EnableScittCompliance.Should().BeFalse(
            "Setting EnableScittCompliance via the shared interface must affect the underlying provider behavior");

        CoseHeaderMap headers = provider.GetProtectedHeaders();
        headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims).Should().BeFalse(
            "Disabling SCITT compliance through the shared interface must suppress default CWT claim emission");
    }
}
