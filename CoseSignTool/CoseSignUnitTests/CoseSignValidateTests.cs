// ----------------------------------------------------------------------------------------
// <copyright file="CoseSignValidateTests.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignUnitTests
{
    using CoseX509;
    using CoseSignTool;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Collections.Generic;
    using System.Formats.Cbor;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Cose;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Diagnostics;

    [TestClass]
    public class CoseSignValidateTests
    {
        private readonly byte[] Payload1 = Encoding.ASCII.GetBytes("Payload1!");
        private const string SubjectName1 = "cn=FakeCert1";
        private const string TestCertStoreName = "CoseSignTestCertStore";

        private static readonly X509Certificate2 SelfSignedCert = HelperFunctions.GenerateTestCert(SubjectName1);
        private static readonly X509Certificate2 SelfSignedRoot = HelperFunctions.GenerateTestCert(SubjectName1);
        private static readonly X509Certificate2 ChainedCert = HelperFunctions.GenerateChainedCert(SelfSignedRoot);

        private static string PrivateKeyCertFile;
        private static string PublicKeyCertFile;
        private static string PayloadFile;

        private static bool ElevatedTests = false;

        public CoseSignValidateTests()
        {
            // export generated certs to files
            PrivateKeyCertFile = HelperFunctions.CreateTemporaryFile() + ".pfx";
            File.WriteAllBytes(PrivateKeyCertFile, SelfSignedCert.Export(X509ContentType.Pkcs12));
            PublicKeyCertFile = HelperFunctions.CreateTemporaryFile() + ".cer";
            File.WriteAllBytes(PublicKeyCertFile, SelfSignedCert.Export(X509ContentType.Cert));

            // make payload file
            PayloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllBytes(PayloadFile, Payload1);

            // Add test cert to test cert store if on Windows
            if (OperatingSystem.IsWindows())
            {
                using (var certStore = new X509Store(TestCertStoreName, StoreLocation.CurrentUser))
                {
                    certStore.Open(OpenFlags.ReadWrite);
                    certStore.Add(SelfSignedCert);
                }
            }
        }

        [TestMethod]
        public void FromMain()
        {
            // sign detached
            string[] args1 = { "sign", @"/pfx", PrivateKeyCertFile, @"/p", PayloadFile };
            Assert.AreEqual(0, CoseSignTool.Main(args1), "Detach sign failed.");

            // sign embedded
            string[] args2 = { "sign", @"/pfx", PrivateKeyCertFile, @"/p", PayloadFile, @"/ep" };
            Assert.AreEqual(0, CoseSignTool.Main(args2), "Embed sign failed.");

            // validate detached
            string sigFile = PayloadFile + ".cose";
            string[] args3 = { "validate", @"/x5", PublicKeyCertFile, @"/sf", sigFile, @"/p", PayloadFile };
            Assert.AreEqual(0, CoseSignTool.Main(args3), "Detach validation failed.");

            // validate embedded
            sigFile = PayloadFile + ".csm";
            string[] args4 = { "validate", @"/x5", PublicKeyCertFile, @"/sf", sigFile };
            Assert.AreEqual(0, CoseSignTool.Main(args4), "Embed validation failed.");

            // validate and retrieve content
            string saveFile = PayloadFile + ".saved";
            string[] args5 = { "validate", @"/x5", PublicKeyCertFile, @"/sf", sigFile, "/sp", saveFile };
            Assert.AreEqual(0, CoseSignTool.Main(args5), "Detach validation with save failed.");
            Assert.AreEqual(File.ReadAllText(PayloadFile), File.ReadAllText(saveFile), "Saved content did not match payload.");
        }

        [TestMethod]
        public void ValidateCoseRoundTripDetached()
        {
            var rsaPublicKey = SelfSignedCert.GetRSAPublicKey();
            var rsaPrivateKey = SelfSignedCert.GetRSAPrivateKey();

            byte[] encodedMsg = CoseSign1Message.Sign(Payload1, rsaPrivateKey, HashAlgorithmName.SHA256, true);
            CoseSign1Message msg = CoseMessage.DecodeSign1(encodedMsg);
            Assert.IsTrue(msg.Verify(rsaPublicKey, Payload1), "Validated CoseSign1Message");
        }

        [TestMethod]
        public void ValidateCoseRoundTripCustomHeader()
        {
            // This test does not actually test any of our code. It just validates the Cose APIs that we're calling.
            var rsaPublicKey = SelfSignedCert.GetRSAPublicKey();
            var rsaPrivateKey = SelfSignedCert.GetRSAPrivateKey();

            var writer = new CborWriter();
            writer.WriteStartArray(definiteLength: 3);
            writer.WriteInt32(42);
            writer.WriteTextString("foo");
            writer.WriteTextString("bar");
            writer.WriteEndArray();

            var myArrayHeader = new CoseHeaderLabel("my-array-header");

            CoseHeaderMap unprotectedHeaders = new();
            unprotectedHeaders.SetEncodedValue(myArrayHeader, writer.Encode());

            // Encode but with user-defined headers.
            byte[] encodedMsg = CoseSign1Message.Sign(Payload1, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders, rsaPrivateKey, HashAlgorithmName.SHA256, isDetached: true);

            CoseSign1Message msg = CoseMessage.DecodeSign1(encodedMsg);

            var encodedHeader = msg.UnprotectedHeaders.GetEncodedValue(myArrayHeader);
            CborReader reader = new(encodedHeader);
            Assert.AreEqual(CborReaderState.StartArray, reader.PeekState(), "encoded as array");

            // If the structure is wrong this will throw an exception and break the test
            Assert.AreEqual(3, reader.ReadStartArray());
            Assert.AreEqual(42, reader.ReadInt32());
            Assert.AreEqual("foo", reader.ReadTextString());
            Assert.AreEqual("bar", reader.ReadTextString());
            reader.ReadEndArray();

            Assert.IsTrue(msg.Verify(rsaPublicKey, Payload1), "Validated CoseSign1Message");
        }

        [TestMethod]
        public void SignValidateInternalTests()
        {
            var signedFile = HelperFunctions.CreateTemporaryFile();
            CoseParser.Sign(Payload1, false, SelfSignedCert, signedFile);

            var signedBytes = File.ReadAllBytes(signedFile);

            List<X509Certificate2> roots = new() { SelfSignedCert };
            CoseParser.ValidateInternal(signedBytes, Payload1, roots, X509RevocationMode.NoCheck, null);
        }

        [TestMethod]
        public void SelfSignedValidateFailIfCertNotPassedAsRoot()
        {
            var signedFile = HelperFunctions.CreateTemporaryFile();
            CoseParser.Sign(Payload1, false, SelfSignedCert, signedFile);

            var signedBytes = File.ReadAllBytes(signedFile);

            List<X509Certificate2> roots = new();
            Assert.ThrowsException<CoseValidationException>(
                () => CoseParser.ValidateInternal(signedBytes, Payload1, roots, X509RevocationMode.NoCheck, null));
        }

        [TestMethod]
        public void EmbeddedFromPayloadFile()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert, true);

            string signedFile = payloadFile + ".csm";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            CoseParser.Validate(signedFile, new List<X509Certificate2>() { SelfSignedCert }, X509RevocationMode.NoCheck);
            Assert.IsTrue(CoseParser.TryValidate(signedFile, new List<X509Certificate2>() { SelfSignedCert }, out Exception ex, X509RevocationMode.NoCheck));
        }

        [TestMethod]
        [ExpectedException(typeof(CoseValidationException))]
        public void EmbeddedBadRoot()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert, true);

            string signedFile = payloadFile + ".csm";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            Assert.IsFalse(CoseParser.TryValidate(signedFile, new List<X509Certificate2>() { ChainedCert }, out Exception ex, X509RevocationMode.NoCheck));
            CoseParser.Validate(signedFile, new List<X509Certificate2>() { ChainedCert }, X509RevocationMode.NoCheck);
        }

        [TestMethod]
        public void DetachedWithRootFiles()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert);

            string signedFile = payloadFile + ".cose";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            CoseParser.Validate(signedFile, payloadFile, new List<X509Certificate2>() { SelfSignedCert }, X509RevocationMode.NoCheck);
            Assert.IsTrue(CoseParser.TryValidate(signedFile, payloadFile, new List<X509Certificate2>() { SelfSignedCert }, out Exception ex, X509RevocationMode.NoCheck));
        }

        [TestMethod]
        [ExpectedException(typeof(CoseValidationException))]
        public void DetachedValidateModifiedPayload()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert);

            string signedFile = payloadFile + ".cose";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            File.WriteAllText(payloadFile, "modified payload");

            Assert.IsFalse(CoseParser.TryValidate(signedFile, payloadFile, new List<X509Certificate2>() { SelfSignedCert }, out Exception ex, X509RevocationMode.NoCheck));
            Assert.AreEqual(ex.GetType().ToString(), typeof(CoseValidationException).ToString());
            CoseParser.Validate(signedFile, payloadFile, new List<X509Certificate2>() { SelfSignedCert }, X509RevocationMode.NoCheck);
        }

        [TestCategory("WindowsOnly"), TestMethod]
        public void EmbeddedFromPayloadFileCertStore()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert, true);

            string signedFile = payloadFile + ".csm";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            CoseParser.Validate(signedFile, new List<string>() { SelfSignedCert.Thumbprint }, TestCertStoreName, StoreLocation.CurrentUser);
            Assert.IsTrue(CoseParser.TryValidate(signedFile, new List<string>() { SelfSignedCert.Thumbprint }, out Exception ex, TestCertStoreName, StoreLocation.CurrentUser));
        }

        [TestCategory("WindowsOnly"), TestMethod]
        public void DetachedFromStoreCert()
        {
            string thumbprint = SelfSignedCert.Thumbprint;

            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, thumbprint, false, null, TestCertStoreName);

            string signedFile = payloadFile + ".cose";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            var storeCert = CertificateStoreHelper.LookupCertificate(thumbprint, TestCertStoreName, StoreLocation.CurrentUser);
            Assert.AreEqual(storeCert, SelfSignedCert);

            // Test that corresponding Validate() and TryValidate() methods succeed
            CoseParser.Validate(signedFile, payloadFile, new List<string>() { thumbprint }, TestCertStoreName, StoreLocation.CurrentUser, X509RevocationMode.NoCheck);
            Assert.IsTrue(CoseParser.TryValidate(signedFile, payloadFile, new List<string>() { thumbprint }, out Exception ex, TestCertStoreName, StoreLocation.CurrentUser, X509RevocationMode.NoCheck));
        }

        [TestCategory("WindowsOnly"), TestMethod]
        public void TrySignDetachedFromStoreCert()
        {
            string thumbprint = SelfSignedCert.Thumbprint;

            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            Assert.IsTrue(CoseParser.TrySign(payloadFile, thumbprint, out Exception ex, false, null, TestCertStoreName));

            string signedFile = payloadFile + ".cose";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            var storeCert = CertificateStoreHelper.LookupCertificate(thumbprint, TestCertStoreName, StoreLocation.CurrentUser);
            Assert.AreEqual(storeCert, SelfSignedCert);

            // Test that signed file can be validated
            CoseParser.Validate(signedFile, payloadFile, new List<string>() { thumbprint }, TestCertStoreName, StoreLocation.CurrentUser, X509RevocationMode.NoCheck);
            Assert.IsTrue(CoseParser.TryValidate(signedFile, payloadFile, new List<string>() { thumbprint }, out Exception ex1, TestCertStoreName, StoreLocation.CurrentUser, X509RevocationMode.NoCheck));
        }

        [TestMethod]
        public void GetEmbeddedPayload()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert, true);
            string signedFile = payloadFile + ".csm";

            List<X509Certificate2> roots = new() { SelfSignedCert };

            var payloadBytes = File.ReadAllBytes(payloadFile);

            // Test that corresponding GetPayload() and TryGetPayload() succeed
            byte[] payload = CoseParser.GetPayload(signedFile, roots, X509RevocationMode.NoCheck);
            Assert.IsTrue(payloadBytes.SequenceEqual(payload));

            Assert.IsTrue(CoseParser.TryGetPayload(signedFile, roots, out byte[] payload1, out Exception ex, X509RevocationMode.NoCheck));
            Assert.IsTrue(payloadBytes.SequenceEqual(payload1));
        }

        [TestCategory("WindowsOnly"), TestMethod]
        public void GetEmbeddedPayloadCertStore()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, SelfSignedCert, true);
            string signedFile = payloadFile + ".csm";

            List<string> thumbprints = new() { SelfSignedCert.Thumbprint };

            var payloadBytes = File.ReadAllBytes(payloadFile);

            // Test that corresponding GetPayload() and TryGetPayload() succeed
            byte[] payload = CoseParser.GetPayload(signedFile, thumbprints, TestCertStoreName, StoreLocation.CurrentUser, X509RevocationMode.NoCheck);
            Assert.IsTrue(payloadBytes.SequenceEqual(payload));

            Assert.IsTrue(CoseParser.TryGetPayload(signedFile, thumbprints, out byte[] payload1, out Exception ex, TestCertStoreName, StoreLocation.CurrentUser, X509RevocationMode.NoCheck));
            Assert.IsTrue(payloadBytes.SequenceEqual(payload1));
        }

        [TestMethod]
        public void CanValidateChainedCertWithRootOrWithFlagSet()
        {
            // Sign the file
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");
            var roots = new List<X509Certificate2>() { SelfSignedRoot };
            CoseParser.Sign(payloadFile, ChainedCert, false, null, roots);

            // Get the signature file
            string signedFile = payloadFile + ".cose";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            // Validate with roots
            CoseParser.Validate(signedFile, payloadFile, roots, X509RevocationMode.NoCheck);

            // Validate without roots, flag set
            CoseParser.Validate(signedFile, payloadFile, null, X509RevocationMode.NoCheck, null, true);

            // Validate without roots, flag not set
            Assert.ThrowsException<CoseValidationException>(() =>
                CoseParser.Validate(signedFile, payloadFile, null, X509RevocationMode.NoCheck));
        }

        [TestMethod]
        public void ThrowsOnSignWithMissingRoot()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            // Note that it throws the same exception regardless of whether AllowUntrusted is set or not.
            Assert.ThrowsException<CoseSigningException>(() => CoseParser.Sign(payloadFile, ChainedCert), "Should have thrown on non-self-signed cert without root.");
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (OperatingSystem.IsWindows()) 
            { 
                using X509Store testCertStore = new(TestCertStoreName, StoreLocation.CurrentUser);
                testCertStore.Open(OpenFlags.ReadWrite);
                testCertStore.RemoveRange(testCertStore.Certificates);
                testCertStore.Close();

                if (ElevatedTests) {
                    using X509Store trustedRootsCertStore = new(StoreName.Root, StoreLocation.CurrentUser);
                    trustedRootsCertStore.Open(OpenFlags.ReadWrite);
                    trustedRootsCertStore.Remove(SelfSignedCert);
                    trustedRootsCertStore.Close();
                }
            }
        }

#if false
        // This test requires elevated permissions because we need to install test cert to Root CA store
        [TestCategory("WindowsOnly"), TestMethod]
        public void ValidateFromRootCAStoreCert()
        {
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            // sign detached
            string[] args1 = { "sign", @"/pfx", PrivateKeyCertFile, @"/p", payloadFile };
            Assert.AreEqual(0, CoseSignTool.Main(args1), "Detach sign failed.");
            string detachedSigFile = payloadFile + ".cose";

            // sign embedded
            string[] args2 = { "sign", @"/pfx", PrivateKeyCertFile, @"/p", payloadFile, @"/ep" };
            Assert.AreEqual(0, CoseSignTool.Main(args2), "Embed sign failed.");
            string embedSigFile = payloadFile + ".csm";

            ElevatedTests = true;
            using (var certStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(SelfSignedCert);
            }
                
            // validate detached
            CoseParser.Validate(detachedSigFile, payloadFile, X509RevocationMode.NoCheck);
            Assert.IsTrue(CoseParser.TryValidate(detachedSigFile, payloadFile, out Exception ex1, X509RevocationMode.NoCheck));

            //validate embedded
            CoseParser.Validate(embedSigFile, X509RevocationMode.NoCheck);
            Assert.IsTrue(CoseParser.TryValidate(embedSigFile, out Exception ex2, X509RevocationMode.NoCheck));
        }
#endif
    }
}