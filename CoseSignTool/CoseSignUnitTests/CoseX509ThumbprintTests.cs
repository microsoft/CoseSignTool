// ----------------------------------------------------------------------------------------
// <copyright file="CoseX509ThumbprintTests.cs" company="Microsoft">
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

    [TestClass]
    public class CoseX509ThumbprintTests
    {

        private const string SubjectName1 = "cn=FakeCert1";
        private const string SubjectName2 = "cn=FakeCert2";
        private static readonly X509Certificate2 SelfSignedCert1 = HelperFunctions.GenerateTestCert(SubjectName1);
        private static readonly X509Certificate2 SelfSignedCert2 = HelperFunctions.GenerateTestCert(SubjectName2);

        private static readonly Dictionary<string, HashAlgorithmName> HashNameToHashAlgoName = new()
        {
            { "SHA1", HashAlgorithmName.SHA1 },
            { "SHA256", HashAlgorithmName.SHA256 },
            { "SHA384", HashAlgorithmName.SHA384 },
            { "SHA512", HashAlgorithmName.SHA512 }
        };


        [TestMethod]
        public void ConstructThumbprintDefaultAlgo() 
        {
            CoseX509Thumprint th = new(SelfSignedCert1);
            HashAlgorithm hashAlgorithm = SHA256.Create();
            Assert.IsTrue(hashAlgorithm.ComputeHash(SelfSignedCert1.RawData).SequenceEqual(th.Thumbprint.ToArray()));
            Assert.IsTrue(th.Match(SelfSignedCert1));
            Assert.IsFalse(th.Match(SelfSignedCert2));
        }
        
        [TestMethod]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void ConstructThumbprintWithAlgo(string algo)
        {
            CoseX509Thumprint th = new(SelfSignedCert1, HashNameToHashAlgoName[algo]);
            HashAlgorithm hashAlgorithm = HashAlgorithm.Create(algo);
            Assert.IsTrue(hashAlgorithm.ComputeHash(SelfSignedCert1.RawData).SequenceEqual(th.Thumbprint.ToArray()));
            Assert.IsTrue(th.Match(SelfSignedCert1));
            Assert.IsFalse(th.Match(SelfSignedCert2));
        }

        [TestMethod]
        [ExpectedException(typeof(CoseX509FormatException))]
        public void ConstructThumbprintWithUnsupportedAlgo()
        {
            CoseX509Thumprint th = new(SelfSignedCert1, HashAlgorithmName.MD5);
        }
    }
}