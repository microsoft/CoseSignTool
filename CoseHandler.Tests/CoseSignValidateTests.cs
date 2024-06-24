// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

using CoseIndirectSignature;
using CoseX509;

[TestClass]
public class CoseHandlerSignValidateTests
{
    private static readonly byte[] Payload1Bytes = Encoding.ASCII.GetBytes("Payload1!");

    // Certificates and chains as objects
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateUtils.CreateCertificate(nameof(CoseHandlerSignValidateTests) + " self signed");    // A self-signed cert
    private static readonly X509Certificate2Collection CertChain1 = TestCertificateUtils.CreateTestChain(nameof(CoseHandlerSignValidateTests) + " set 1");      // Two complete cert chains
    private static readonly X509Certificate2Collection CertChain2= TestCertificateUtils.CreateTestChain(nameof(CoseHandlerSignValidateTests) + " set 2");
    private static readonly X509Certificate2 Root1Priv = CertChain1[0];                                                                                         // Roots from the chains
    private static readonly X509Certificate2 Root2Priv = CertChain2[0];
    private static readonly X509Certificate2 Int1Priv = CertChain1[1];
    private static readonly X509Certificate2 Leaf1Priv = CertChain1[^1];                                                                                        // Leaf node certs
    private static readonly X509Certificate2 Leaf2Priv = CertChain2[^1];

    // As byte arrays
    private static readonly byte[] Pfx1 = CertChain1.Export(X509ContentType.Pkcs12)!;
    private static readonly byte[] Root1Cer = Root1Priv.Export(X509ContentType.Cert);
    private static readonly byte[] Root2Cer = Root2Priv.Export(X509ContentType.Cert);
    private static readonly byte[] Int1Cer = Int1Priv.Export(X509ContentType.Cert);

    // As public key certs
    private static readonly X509Certificate2 Root1Pub = new(Root1Cer);
    private static readonly X509Certificate2 Int1Pub = new(Int1Cer);

    // As lists
    private static readonly List<X509Certificate2> ValidRootSetPriv = [Root1Priv, Int1Priv];                                                  // Root and intermediate only
    private static readonly List<X509Certificate2> ValidRootSetPub = [Root1Pub, Int1Pub];

    // File paths to export them to
    private static readonly string PrivateKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.pfx";
    private static readonly string PublicKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.cer";
    private static readonly string PrivateKeyRootCertFile = Path.GetTempFileName() + ".pfx";
    private static readonly string PublicKeyRootCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PrivateKeyCertFileChained = Path.GetTempFileName() + ".pfx";
    private readonly string PayloadFile = Path.GetTempFileName();
    private readonly string TestFolder;

    private static readonly CoseSign1MessageValidator BaseValidator = new X509ChainTrustValidator(
                ValidRootSetPriv,
                RevMode,
                allowUnprotected: true,
                allowUntrusted: true);

    private static readonly X509RevocationMode RevMode = X509RevocationMode.NoCheck;

    public CoseHandlerSignValidateTests()
    {
        // set paths
        TestFolder = Path.GetDirectoryName(PayloadFile) + Path.DirectorySeparatorChar;

        // export generated certs to files
        File.WriteAllBytes(PrivateKeyCertFileSelfSigned, SelfSignedCert.Export(X509ContentType.Pkcs12));
        File.WriteAllBytes(PublicKeyCertFileSelfSigned, SelfSignedCert.Export(X509ContentType.Cert));        
        File.WriteAllBytes(PrivateKeyRootCertFile, Root1Priv.Export(X509ContentType.Pkcs12));        
        File.WriteAllBytes(PublicKeyRootCertFile, Root1Priv.Export(X509ContentType.Cert));        
        File.WriteAllBytes(PrivateKeyCertFileChained, Leaf1Priv.Export(X509ContentType.Pkcs12));

        // write payload file
        File.WriteAllBytes(PayloadFile, Payload1Bytes);
    }

    #region Valid Sign/Validate scenarios: Payload and signature options
    /// <summary>
    /// This is the most basic round trip scenario. Detach sign the payload from a byte array with a chained cert,
    /// then validate the signed bytes against the chained cert and its root. No file reads, store lookups, streams,
    /// config options, or dependence on default behaviors.
    /// Consider these the default options for other round trip tests.
    /// </summary>
    [TestMethod]
    public void Base_DetachSignBytesChainedCert_ValidateBytesRoots()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv, false, null);
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode)
            .Success.Should().Be(true);
    }

    /// <summary>
    /// Validates that signature from stream can validate from bytes.
    /// </summary>
    [TestMethod]
    public void StreamPayloadIn()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(new MemoryStream(Payload1Bytes), Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode)
            .Success.Should().Be(true);
    }

    /// <summary>
    /// Validates that signature from bytes can validate from stream.
    /// </summary>
    [TestMethod]
    public void StreamPayloadOut()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        var results = CoseHandler.Validate(signedBytes.ToArray(), new MemoryStream(Payload1Bytes), ValidRootSetPriv, RevMode);
        results.Success.Should().Be(true);
    }

    /// <summary>
    /// Validates the file read/write operations for payload and signatures.
    /// </summary>
    [TestMethod]
    public void PayloadFile_SignatureFile()
    {
        string signaturePath = $"{TestFolder}{nameof(PayloadFile_SignatureFile)}.cose";
        FileInfo signatureFile = new (signaturePath);
        byte[] signedBytes = CoseHandler.Sign(new FileInfo(PayloadFile), Leaf1Priv, false, signatureFile).ToArray();
        signedBytes.Should().NotBeNull();
        byte[] bytesFromFile = File.ReadAllBytes(signaturePath);
        bytesFromFile.Should().Equal(signedBytes);

        // Validate from bytes
        CoseHandler.Validate(signedBytes, Payload1Bytes, ValidRootSetPriv, RevMode)
            .Success.Should().Be(true);

        // Validate from stream
        FileInfo sigFile = new (signaturePath);
        CoseHandler.Validate(sigFile.GetStreamResilient(), Payload1Bytes, ValidRootSetPriv, RevMode)
            .Success.Should().Be(true);
    }

    /// <summary>
    /// Validate the SigningKeyProvider syntax, the internal GetValidator function, and the object handling for unspecified payload and signature inputs.
    /// </summary>
    [TestMethod]
    public void WithSigningKeyProviderAndChainValidator()
    {
        //string signatureFile = $"{TestFolder}WithSigningKeyProviderAndChainValidator.cose";

        // Sign bytes, validate stream
        ReadOnlyMemory<byte> signedBytesB = CoseHandler.Sign(Payload1Bytes, new X509Certificate2CoseSigningKeyProvider(null, Leaf1Priv));
        signedBytesB.ToArray().Should().NotBeNull();
        var result = CoseHandler.Validate(signedBytesB.ToArray(), BaseValidator, new MemoryStream(Payload1Bytes));
        result.Success.Should().Be(true);

        // Sign stream, validate bytes
        ReadOnlyMemory<byte> signedBytesS = CoseHandler.Sign(new MemoryStream(Payload1Bytes), new X509Certificate2CoseSigningKeyProvider(null, Leaf1Priv));
        signedBytesS.ToArray().Should().NotBeNull();
        result = CoseHandler.Validate(signedBytesS.ToArray(), BaseValidator, Payload1Bytes);
        result.Success.Should().Be(true);
    }
    #endregion

    #region Valid Sign/Validate scenarios: Other options
    /// <summary>
    /// Validate that embed signing works and that GetPayload gets the same content that went in.
    /// </summary>
    [TestMethod]
    public void EmbedSign_Get()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv, true);
        signedBytes.ToArray().Should().NotBeNull();
        var returnedPayload = CoseHandler.GetPayload(signedBytes.ToArray(), out _, ValidRootSetPriv, RevMode);
        returnedPayload.Should().Be("Payload1!");
    }

    /// <summary>
    /// Validates that a HeaderExtender is added when specified.
    /// </summary>
    [TestMethod]
    public void HeaderExtender()
    {
        // TODO: Fill in this test -- currently a place holder
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode)
            .Success.Should().Be(true);
    }


    [TestMethod]
    public void FromCertStoreWithThumbs()
    {
        // TODO: Fill in this test -- currently a place holder. Remember -- only the Sign op can take a thumbprint.
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode);
    }

    [TestMethod]
    public void FromCertStoreNoThumbs()
    {
        // TODO: Fill in this test -- currently a place holder. This is for basically default sign -- not sure if it's something we should support or test.
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode);
    }

    /// <summary>
    /// Validate that signing with requiredCommonName set passes validation when and only when the cert has the correct common name.
    /// </summary>
    [TestMethod]
    public void CommonName()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        string validCommonName = Leaf1Priv.Subject;

        var result = CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode, requiredCommonName: "Not the cert common name");
        result.Success.Should().Be(false);

        result = CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, ValidRootSetPriv, RevMode, requiredCommonName: validCommonName);
        result.Success.Should().Be(true);
    }

    /// <summary>
    /// Validates with chained cert against a blank validator.
    /// </summary>
    [TestMethod]
    public void BlankValidator()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), new X509ChainTrustValidator(), Payload1Bytes)
            .Success.Should().Be(false);
    }

    /// <summary>
    /// Validates that passed in roots are considered "trusted"
    /// </summary>
    [TestMethod]
    public void TrustProvidedRoots()
    {
        // Sign, then validate with a custom validator that does not allow untrusted chains
        X509ChainTrustValidator chainValidator = new(ValidRootSetPub, RevMode);
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv, false);
        CoseHandler.Validate(signedBytes.ToArray(), chainValidator, Payload1Bytes)
            .Success.Should().Be(true);
    }

    /// <summary>
    /// Validate that signing with a self-signed cert causes validation to return ValidationResultTypes.ValidUntrusted
    /// </summary>
    [TestMethod]
    public void SelfSigned()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, SelfSignedCert);
        signedBytes.ToArray().Should().NotBeNull();
        var result = CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, [SelfSignedCert], RevMode);
        result.Success.Should().Be(true);
    }

    /// <summary>
    /// Validate that signing with an untrusted cert causes validation to fail
    /// </summary>
    [TestMethod]
    public void Untrusted()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, new X509Certificate2(PrivateKeyCertFileChained));
        signedBytes.ToArray().Should().NotBeNull();
        CoseHandler.Validate(signedBytes.ToArray(), Payload1Bytes, null, RevMode)
            .Success.Should().Be(false);
    }

    /// <summary>
    /// Validate that signing with an untrusted cert causes validation to return ValidationResultTypes.ValidUntrusted
    /// </summary>
    [TestMethod]
    public void UntrustedAllowedSelfSigned()
    {
        // Self signed cert should pass when AllowUntrusted is true.
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, new X509Certificate2(PrivateKeyCertFileSelfSigned));
        signedBytes.ToArray().Should().NotBeNull();
        X509ChainTrustValidator chainValidator = new(revocationMode: RevMode, allowUntrusted: true);
        ValidationResult result = CoseHandler.Validate(signedBytes.ToArray(), chainValidator, Payload1Bytes);
        result.Success.Should().Be(true);
        result.InnerResults?.Count.Should().Be(1);
        result.InnerResults?[0]?.PassedValidation.Should().BeTrue();
        result.InnerResults?[0]?.ResultMessage.Should().Be("Certificate was allowed because AllowUntrusted was specified.");
    }

    /// <summary>
    /// Test that validation with AllowUntrusted will still fail if required roots are not found.
    /// </summary>
    [TestMethod]
    public void UntrustedAllowedChainedCert()
    {
        // Chained cert should fail even when AllowUntrusted is true because it doesn't chain to any root, trusted or otherwise.
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, new X509Certificate2(PrivateKeyCertFileChained));
        signedBytes.ToArray().Should().NotBeNull();
        X509ChainTrustValidator chainValidator = new(revocationMode: RevMode, allowUntrusted: true);
        ValidationResult result = CoseHandler.Validate(signedBytes.ToArray(), chainValidator, Payload1Bytes);
        result.Success.Should().Be(false);
        result.InnerResults?.Count.Should().Be(1);
        result.InnerResults?[0]?.PassedValidation.Should().BeFalse();
    }
    #endregion

    #region Error scenarios
    [TestMethod]
    public void DetachedValidationWithoutPayload()
    {
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        signedBytes.ToArray().Should().NotBeNull();
        var result = CoseHandler.Validate(signedBytes.ToArray(), BaseValidator);

        result.Success.Should().Be(false);
        result.Errors.Should().Contain(e => e.ErrorCode.Equals(ValidationFailureCode.PayloadMissing));
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void SignWithoutPayload()
    {
#pragma warning disable CS8600, CS8625 // Converting null literal -- deliberate null convetrsion for test purposes.
        _ = CoseHandler.Sign((byte[]) null, Leaf1Priv);
#pragma warning restore CS8600, CS8625 // Converting null literal or possible null value to non-nullable type.
    }

    [TestMethod]
    public void DetachedValidateModifiedPayload()
    {
        // Standard setup
        ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);

        // Now change one character in the payload
        var modifiedPayload = Encoding.ASCII.GetBytes("Payload2!");

        // Try to validate
        var result = CoseHandler.Validate(signedBytes.ToArray(), modifiedPayload, ValidRootSetPriv, RevMode);

        result.Success.Should().Be(false);
        result.Errors.Should().Contain(e => e.ErrorCode.Equals(ValidationFailureCode.PayloadMismatch));
    }

    [TestMethod]
    public void IndirectSignatureValidation()
    {
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: Payload1Bytes,
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(Leaf1Priv)).ToArray();

        // Try to validate byte[]
        var result = CoseHandler.Validate(signedBytes, Payload1Bytes, ValidRootSetPriv, RevMode);
        result.Success.Should().Be(true);

        // Try to validate stream
        var result2 = CoseHandler.Validate(signedBytes, new MemoryStream(Payload1Bytes), ValidRootSetPriv, RevMode);
        result2.Success.Should().Be(true);
    }

    [TestMethod]
    public void IndirectSignatureModifiedPayload()
    {
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: Payload1Bytes,
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(Leaf1Priv)).ToArray();

        // Now change one character in the payload
        var modifiedPayload = Encoding.ASCII.GetBytes("Payload2!");

        // Try to validate byte[]
        var result = CoseHandler.Validate(signedBytes, modifiedPayload, ValidRootSetPriv, RevMode);
        result.Success.Should().Be(false);
        result.Errors.Should().Contain(e => e.ErrorCode.Equals(ValidationFailureCode.PayloadMismatch));

        // Try to validate stream
        var result2 = CoseHandler.Validate(signedBytes, new MemoryStream(modifiedPayload), ValidRootSetPriv, RevMode);
        result2.Success.Should().Be(false);
        result2.Errors.Should().Contain(e => e.ErrorCode.Equals(ValidationFailureCode.PayloadMismatch));
    }

    [TestMethod]
    public void IndirectSignatureUntrustedSignature()
    {
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: Payload1Bytes,
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(Leaf1Priv)).ToArray();

        // Try to validate byte[]
        var result = CoseHandler.Validate(signedBytes, Payload1Bytes, null, RevMode);
        result.Success.Should().Be(false);
        result.Errors.Should().Contain(e => e.ErrorCode.Equals(ValidationFailureCode.TrustValidationFailed));

        // Try to validate stream
        var result2 = CoseHandler.Validate(signedBytes, new MemoryStream(Payload1Bytes), null, RevMode);
        result2.Success.Should().Be(false);
        result2.Errors.Should().Contain(e => e.ErrorCode.Equals(ValidationFailureCode.TrustValidationFailed));
    }
    #endregion

    #region TryX wrappers

    [TestMethod]
    public void SignAllOverloadsAndValidate()
    {
        X509Certificate2CoseSigningKeyProvider keyProvider = new(null, Leaf1Priv);

        var sig2 = CoseHandler.Sign(Payload1Bytes, Leaf1Priv);
        var result = CoseHandler.Validate(sig2.ToArray(), Payload1Bytes, ValidRootSetPub, RevMode);
        result.Success.Should().Be(true);

        var sig3 = CoseHandler.Sign(Payload1Bytes, keyProvider);
        result = CoseHandler.Validate(sig3.ToArray(), Payload1Bytes, ValidRootSetPub, RevMode);
        result.Success.Should().Be(true);

        var sig4 = CoseHandler.Sign(new MemoryStream(Payload1Bytes), keyProvider);
        result = CoseHandler.Validate(sig4.ToArray(), Payload1Bytes, ValidRootSetPub, RevMode);
        result.Success.Should().Be(true);

        var sig5 = CoseHandler.Sign(new MemoryStream(Payload1Bytes), Leaf1Priv);
        result = CoseHandler.Validate(sig5.ToArray(), Payload1Bytes, ValidRootSetPub, RevMode);
        result.Success.Should().Be(true);

        var sig6 = CoseHandler.Sign(new FileInfo(PayloadFile), keyProvider);
        result = CoseHandler.Validate(sig6.ToArray(), Payload1Bytes, ValidRootSetPub, RevMode);
        result.Success.Should().Be(true);

        var sig7 = CoseHandler.Sign(new FileInfo(PayloadFile), Leaf1Priv);
        result = CoseHandler.Validate(sig7.ToArray(), Payload1Bytes, ValidRootSetPub, RevMode);
        result.Success.Should().Be(true);

        // Note: Thumbprint cases area excluded to avoid cert store calls.
    }
    #endregion
}
