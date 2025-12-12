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
}
