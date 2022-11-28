// ----------------------------------------------------------------------------------------
// <copyright file="CoseX509CertificatesTests.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignUnitTests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System.Formats.Cbor;
    using System.Security.Cryptography.X509Certificates;
    using CoseX509;

    [TestClass]
    public class CoseX509CertificatesTests
    {
        [TestMethod]
        public void CoseX509Certificates_EncodeCertList_OneCert()
        {
            X509Certificate2Collection expectedCerts = new()
            {
                HelperFunctions.GenerateTestCert("cn=test1")
            };

            CborWriter cborWriter = new();
            cborWriter.WriteTextString("woohoo");
            cborWriter.EncodeCertList(expectedCerts);

            CborReader cborReader = new(cborWriter.Encode());

            Assert.AreEqual(CborReaderState.ByteString, cborReader.PeekState(), "Validate that the writer was reset");
            //Work through the structure as CborReader will throw if the state machine does not match the read request
            _ = cborReader.ReadByteString();
        }

        [TestMethod]
        public void CoseX509Certificates_EncodeCertList_TwoCerts()
        {
            X509Certificate2Collection expectedCerts = new()
            {
                HelperFunctions.GenerateTestCert("cn=test1"),
                HelperFunctions.GenerateTestCert("cn=test2")
            };

            CborWriter cborWriter = new();
            cborWriter.WriteTextString("woo");
            cborWriter.EncodeCertList(expectedCerts);

            CborReader cborReader = new(cborWriter.Encode());

            Assert.AreEqual(CborReaderState.StartArray, cborReader.PeekState(), "Validate that the writer was reset and starts with an array");
            Assert.AreEqual(expectedCerts.Count, cborReader.ReadStartArray(), "Array sizes match");
            //Work through the structure as CborReader will throw if the state machine does not match the read request
            _ = cborReader.ReadByteString();
            _ = cborReader.ReadByteString();
            cborReader.ReadEndArray();
        }
    }
}