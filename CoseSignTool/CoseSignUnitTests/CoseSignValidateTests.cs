// ----------------------------------------------------------------------------------------
// <copyright file="CoseSignValidateTests.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignUnitTests
{
    using CoseX509;
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

    [TestClass]
    public class CoseSignValidateTests
    {
        private readonly byte[] payload1 = Encoding.ASCII.GetBytes("Payload1!");
        private const string subjectName1 = "cn=FakeCert1";

        [TestMethod]
        public void ValidateCoseRoundTripDetached()
        {
            // This test does not actually test any of our code. It just validates the Cose APIs that we're calling.
            var cert = HelperFunctions.GenerateTestCert(subjectName1);

            var rsaPublicKey = cert.GetRSAPublicKey();
            var rsaPrivateKey = cert.GetRSAPrivateKey();

            byte[] encodedMsg = CoseSign1Message.Sign(payload1, rsaPrivateKey, HashAlgorithmName.SHA256, true);
            CoseSign1Message msg = CoseMessage.DecodeSign1(encodedMsg);
            Assert.IsTrue(msg.Verify(rsaPublicKey, payload1), "Validated CoseSign1Message");
        }

        [TestMethod]
        public void ValidateCoseRoundTripCustomHeader()
        {
            // This test does not actually test any of our code. It just validates the Cose APIs that we're calling.
            var cert = HelperFunctions.GenerateTestCert(subjectName1);

            var rsaPublicKey = cert.GetRSAPublicKey();
            var rsaPrivateKey = cert.GetRSAPrivateKey();

            var writer = new CborWriter();
            writer.WriteStartArray(definiteLength: 3);
            writer.WriteInt32(42);
            writer.WriteTextString("foo");
            writer.WriteTextString("bar");
            writer.WriteEndArray();

            var myArrayHeader = new CoseHeaderLabel("my-array-header");

            CoseHeaderMap unprotectedHeaders = new CoseHeaderMap();
            unprotectedHeaders.SetEncodedValue(myArrayHeader, writer.Encode());

            // Encode but with user-defined headers.
            byte[] encodedMsg = CoseSign1Message.Sign(payload1, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders, rsaPrivateKey, HashAlgorithmName.SHA256, isDetached: true);

            CoseSign1Message msg = CoseMessage.DecodeSign1(encodedMsg);

            var encodedHeader = msg.UnprotectedHeaders.GetEncodedValue(myArrayHeader);
            CborReader reader = new CborReader(encodedHeader);
            Assert.AreEqual(CborReaderState.StartArray, reader.PeekState(), "encoded as array");

            // If the structure is wrong this will throw an exception and break the test
            Assert.AreEqual(3, reader.ReadStartArray());
            Assert.AreEqual(42, reader.ReadInt32());
            Assert.AreEqual("foo", reader.ReadTextString());
            Assert.AreEqual("bar", reader.ReadTextString());
            reader.ReadEndArray();

            Assert.IsTrue(msg.Verify(rsaPublicKey, payload1), "Validated CoseSign1Message");
        }

        [TestMethod]
        public void SignValidateInternalTests()
        {
            var cert = HelperFunctions.GenerateTestCert(subjectName1);

            var signedFile = HelperFunctions.CreateTemporaryFile();
            CoseParser.Sign(payload1, false, cert, signedFile);

            var signedBytes = File.ReadAllBytes(signedFile);

            List<X509Certificate2> roots = new() { cert };
            CoseParser.ValidateInternal(signedBytes, payload1, roots, X509RevocationMode.NoCheck, null);
        }

        [TestMethod]
        public void SelfSignedValidateFailIfCertNotPassedAsRoot()
        {
            var cert = HelperFunctions.GenerateTestCert(subjectName1);

            var signedFile = HelperFunctions.CreateTemporaryFile();
            CoseParser.Sign(payload1, false, cert, signedFile);

            var signedBytes = File.ReadAllBytes(signedFile);

            List<X509Certificate2> roots = new();
            Assert.ThrowsException<CoseValidationException>(
                () => CoseParser.ValidateInternal(signedBytes, payload1, roots, X509RevocationMode.NoCheck, null));
        }

        [TestMethod]
        public void EmbeddedFromPayloadFile()
        {
            var cert = HelperFunctions.GenerateTestCert(subjectName1);
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, cert, true);

            string signedFile = payloadFile + ".csm";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            CoseParser.Validate(signedFile, new List<X509Certificate2>() { cert }, X509RevocationMode.NoCheck);
        }

        [TestMethod]
        public void DetachedFromStoreCert()
        {
            var cert = HelperFunctions.GenerateTestCert(subjectName1);
            using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(cert);
            }
            string thumbprint = cert.Thumbprint;

            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, thumbprint);

            string signedFile = payloadFile + ".cose";
            var dir = Directory.GetParent(payloadFile);
            Assert.IsTrue(File.Exists(signedFile), $"Could not find {signedFile} in directory {dir.FullName}.");

            var storeCert = CertificateStoreHelper.LookupCertificate(thumbprint, "My", StoreLocation.CurrentUser);
            Assert.AreEqual(storeCert, cert);

            CoseParser.Validate(signedFile, payloadFile, new List<string>() { thumbprint }, "My", StoreLocation.CurrentUser, X509RevocationMode.NoCheck);
        }

        [TestMethod]
        public void GetEmbeddedPayload()
        {
            var cert = HelperFunctions.GenerateTestCert(subjectName1);
            string payloadFile = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payloadFile, "Payload");

            CoseParser.Sign(payloadFile, cert, true);
            string signedFile = payloadFile + ".csm";

            byte[] payload = CoseParser.GetPayload(signedFile, new List<X509Certificate2>() { cert }, X509RevocationMode.NoCheck);

            var payloadBytes = File.ReadAllBytes(payloadFile);
            Assert.IsTrue(payloadBytes.SequenceEqual(payload));
        }
    }
}