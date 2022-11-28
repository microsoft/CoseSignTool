// ----------------------------------------------------------------------------------------
// <copyright file="CoseExtensionsTests.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignUnitTests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using CoseX509;
    using System.Linq;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.Cose;
    using System.Text;
    using System.IO;

    [TestClass]
    public class CoseExtensionsTests
    {
        private readonly byte[] Payload1 = Encoding.ASCII.GetBytes("Payload1!");
        private const string SubjectName1 = "cn=FakeCert1";

        private static readonly X509Certificate2 SelfSignedCert = HelperFunctions.GenerateTestCert(SubjectName1);
        private static readonly X509Certificate2 SelfSignedRoot = HelperFunctions.GenerateTestCert(SubjectName1);
        private static readonly X509Certificate2 ChainedCert = HelperFunctions.GenerateChainedCert(SelfSignedRoot);

        [TestMethod]
        public void ValidateCoseSign1Message()
        {
            var signedFile = HelperFunctions.CreateTemporaryFile();
            CoseParser.Sign(Payload1, false, SelfSignedCert, signedFile);

            var signedBytes = File.ReadAllBytes(signedFile);
            var policy = new X509ChainPolicy();
            policy.CustomTrustStore.Add(SelfSignedCert);
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            CoseSign1Message msg = CoseMessage.DecodeSign1(signedBytes);
            Assert.IsTrue(CoseExtensions.VerifyWithX509(msg, Payload1, policy));
        }

        [TestMethod]
        public void TryGetSigningCert()
        {
            var signedFile = HelperFunctions.CreateTemporaryFile();
            var roots = new List<X509Certificate2>() { SelfSignedRoot };
            CoseParser.Sign(Payload1, false, ChainedCert, signedFile, roots);

            var signedBytes = File.ReadAllBytes(signedFile);
            var policy = new X509ChainPolicy();
            policy.CustomTrustStore.Add(SelfSignedRoot);
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.RevocationMode = X509RevocationMode.NoCheck;
            CoseSign1Message msg = CoseMessage.DecodeSign1(signedBytes);

            Assert.IsTrue(CoseExtensions.TryGetSigningCertificate(msg, out X509Certificate2 signCert, out X509Certificate2Collection extras, policy));

            Assert.AreEqual(signCert.Thumbprint, ChainedCert.Thumbprint);
            Assert.AreEqual(extras[0].Thumbprint, SelfSignedRoot.Thumbprint);
        }

        [TestMethod]
        public void TryGetSigningCertBadStatus()
        {
            var signedFile = HelperFunctions.CreateTemporaryFile();
            var roots = new List<X509Certificate2>() { SelfSignedRoot };
            CoseParser.Sign(Payload1, false, ChainedCert, signedFile, roots);

            var signedBytes = File.ReadAllBytes(signedFile);
            var policy = new X509ChainPolicy();
            policy.CustomTrustStore.Add(SelfSignedRoot);
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            CoseSign1Message msg = CoseMessage.DecodeSign1(signedBytes);

            Assert.IsFalse(CoseExtensions.TryGetSigningCertificate(msg, out X509Certificate2 signCert, out X509Certificate2Collection extras, policy));

            Assert.AreEqual(signCert.Thumbprint, ChainedCert.Thumbprint);
            Assert.AreEqual(extras[0].Thumbprint, SelfSignedRoot.Thumbprint);
        }

        [TestMethod]
        public void ValidateCommonName()
        {
            CoseExtensions.ValidateCommonName(SelfSignedRoot, SelfSignedRoot.SubjectName.Name);
        }

        [TestMethod]
        [ExpectedException(typeof(CoseValidationException))]
        public void ValidateCommonNameFail()
        {
            CoseExtensions.ValidateCommonName(SelfSignedRoot, "epic fail");
        }
    }
}