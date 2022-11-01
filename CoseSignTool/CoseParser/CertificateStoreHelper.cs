// ----------------------------------------------------------------------------------------
// <copyright file="CertificateStoreHelper.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Provides static methods for working with accessing certificates in a Windows Certificate Store.
    /// </summary>
    public static class CertificateStoreHelper
    {
        private const string DefaultStoreName = "My";

        /// <summary>
        /// Checks the local Windows certificate store for a certificate matching the specified thumbprint.
        /// </summary>
        /// <param name="thumbprint">The SHA1 thumbprint of the certificate to find.</param>
        /// <param name="storeName">(Optional) The name of the store to check. Default value is 'My'.</param>
        /// <param name="storeLocation">(Optional) The location of the store to check. Default value is CurrentUser.</param>
        /// <returns>The certificate, if found.</returns>
        /// <exception cref="CoseSigningException">The certificate could not be found in the specified store.</exception>
        /// <remarks>This method takes StoreName as a string to allow for custom stores.</remarks>
        public static X509Certificate2 LookupCertificate(string thumbprint, string storeName= DefaultStoreName, StoreLocation storeLocation=StoreLocation.CurrentUser)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new InvalidOperationException("Certificate store operation are only valid on Windows operating systems.");
            }

            //First look up the signing cert in store
            using var certStore = new X509Store(storeName, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);

            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

            return certCollection.FirstOrDefault() ?? throw new CoseSigningException($"Unable to find certificate with thumbprint {thumbprint}");
        }

        /// <summary>
        /// Checks the local Windows certificate store for certificates matching the specified thumbprints.
        /// </summary>
        /// <param name="thumbprints">The SHA1 thumbprints of the certificates to find.</param>
        /// <param name="storeName">(Optional) The name of the store to check. Default value is My.</param>
        /// <param name="storeLocation">(Optional) The location of the store to check. Default value is CurrentUser.</param>
        /// <returns></returns>
        /// <exception cref="CoseSigningException"></exception>
        public static List<X509Certificate2> LookupCertificates(
            List<string> thumbprints,
            string storeName = DefaultStoreName,
            StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new InvalidOperationException("Certificate store operation are only valid on Windows operating systems.");
            }

            //First look up the thumbprints in store
            using var certStore = new X509Store(storeName, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);

            return thumbprints.Select(t => certStore.Certificates.Find(X509FindType.FindByThumbprint, t, validOnly: false)
                .FirstOrDefault() ?? throw new CoseSigningException($"Unable to find certificate with thumbprint {t}"))
                .ToList();

            // TODO: Need to test which version is faster
            // return thumbprints.Select(t => LookupCertificate(t, storeName, storeLocation)).ToList();
        }
    }
}
