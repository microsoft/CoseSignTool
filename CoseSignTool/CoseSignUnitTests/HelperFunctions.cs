// ----------------------------------------------------------------------------------------
// <copyright file="HelperFunctions.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignUnitTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public static class HelperFunctions
    {
        /// <summary>
        /// Generates an X509Certificate2 with a private key.
        /// </summary>
        /// <returns>The certificate.</returns>
        public static X509Certificate2 GenerateTestCert(string subjectName = "cn=FakeCert")
        {
            // Generate asymmetric key pair
            //ECDsa ecdsa = ECDsa.Create();
            var rsa = RSA.Create(3072);
            var req = new CertificateRequest(new X500DistinguishedName(subjectName), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            using (X509Certificate2 requestedCert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5)))
            {
                var persistable = new X509Certificate2(requestedCert.Export(X509ContentType.Pkcs12), "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                return persistable;
            }
        }

        /// <summary>
        /// Generates an X509Certificate2 without a private key.
        /// </summary>
        /// <returns>The certificate.</returns>
        public static X509Certificate2 GeneratePublicKeyCert(string subjectName = "FakeCert")
        {
            X509Certificate2 toStrip = GenerateTestCert(subjectName);
            byte[] rawCert = toStrip.Export(X509ContentType.Cert);
            return new X509Certificate2(rawCert);
        }

        /// <summary>
        /// Creates a randomly named temporary file on disk.
        /// </summary>
        /// <returns>The file name.</returns>
        public static string CreateTemporaryFile()
        {
            string fileName;
            try
            {
                fileName = Path.GetTempFileName();
                FileInfo fileInfo = new(fileName) { Attributes = FileAttributes.Temporary };
            }
            catch (IOException e)
            {
                System.Diagnostics.Debugger.Log(0, "", $"Could not create a temp file: {e.Message}");
                throw;
            }

            return fileName;
        }
    }
}