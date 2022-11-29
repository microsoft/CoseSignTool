// ----------------------------------------------------------------------------------------
// <copyright file="SignCommand.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignTool
{
    using CoseX509;
    using Microsoft.Extensions.Configuration.CommandLine;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Signs a file with a COSE signature based on passed in command line arguments.
    /// </summary>
    public sealed class SignCommand : CoseCommand
    {
        /// <summary>
        /// A map of command line options to their abbreviated aliases.
        /// </summary>
        internal static readonly Dictionary<string, string> Options = new()
        {
            ["-EmbedPayload"] = "EmbedPayload",
            ["-Thumbprint"] = "Thumbprint",
            ["-PfxCertificate"] = "PfxCertificate",
            ["-ep"] = "EmbedPayload",
            ["-th"] = "Thumbprint",
            ["-pfx"] = "PfxCertificate",
        };

        #region Public properties
        /// <summary>
        /// Optional. If true, encrypts and embeds the payload in the in Cose signature file.
        /// Default behavior is 'detached signing', where the signature is in a separate file from the payload.
        /// Note that embed-signed files are not readable by standard text editors.
        /// </summary>
        public bool EmbedPayload { get; set; }

        /// <summary>
        /// Optional. Gets or sets the SHA1 thumbprint of a certificate in the Windows Certificate Store to sign the file with.
        /// </summary>
        public string Thumbprint { get; set; }


        /// <summary>
        /// Optional. Gets or set the path to a private key certificate file (.pfx) to sign with.
        /// </summary>
        public string PfxCertificate { get; set; }
        #endregion

        /// <summary>
        /// For test use only.
        /// </summary>
        internal SignCommand() { }

        /// <summary>
        /// Creates a SignCommand instance and sets its properties with a CommandLineConfigurationProvider.
        /// </summary>
        /// <param name="provider">A CommandLineConfigurationProvider that has loaded the command line arguments.</param>
        public SignCommand(CommandLineConfigurationProvider provider)
        {
            ApplyOptions(provider);

            // Make sure we have a payload file
            ThrowIfNullOrEmpty(Payload, nameof(Payload));
            ThrowIfMissing(Payload, "Payload file not found");
        }

        /// <summary>
        /// Generates a cose signed document for the given certificate and payload
        /// </summary>
        /// <returns>An exit code indicating success or failure.</returns>
        /// <exception cref="FileNotFoundException">The specified payload file or certificate file could not be found.</exception>
        /// <exception cref="ArgumentOutOfRangeException">User passed in a thumbprint instead of a file path on a non-Windows OS.</exception>
        /// <exception cref="ArgumentNullException">No certificate filepath or thumbprint was given.</exception>
        public override ExitCode Run()
        {
            X509Certificate2 cert = LoadCert();

            List<X509Certificate2> extras = null;
            if (X509RootFiles is not null)
            {
                extras = new List<X509Certificate2>();
                foreach (var certPath in X509RootFiles)
                {
                    ThrowIfMissing(certPath, "Could not find the certificate file");
                    extras.Add(new X509Certificate2(certPath));
                }
            }

            // Sign the file
            try
            {
                CoseParser.Sign(Payload, cert, EmbedPayload, SignatureFile, extras);
                return (int)ExitCode.Success;
            }
            catch (Exception ex) when (ex is CryptographicException || ex is CoseSigningException)
            {
                return CoseSignTool.Fail(ExitCode.CertificateLoadFailure, ex);
            }
        }

        //<inheritdoc />
        protected internal override void ApplyOptions(CommandLineConfigurationProvider provider)
        {
            EmbedPayload = GetOptionBool(provider, "EmbedPayload");
            Thumbprint = GetOptionString(provider, "Thumbprint");
            PfxCertificate = GetOptionString(provider, "PfxCertificate");
            base.ApplyOptions(provider);
        }

        /// <summary>
        /// Tries to load the certificate to sign with.
        /// </summary>
        /// <returns>The certificate if found.</returns>
        /// <exception cref="ArgumentOutOfRangeException">User passed in a thumbprint instead of a file path on a non-Windows OS.</exception>
        /// <exception cref="ArgumentNullException">No certificate filepath or thumbprint was given.</exception>
        /// <exception cref="CryptographicException">The certificate was found but could not be loaded.</exception>
        internal X509Certificate2 LoadCert()
        {
            X509Certificate2 cert;
            if (Thumbprint is not null && !OperatingSystem.IsWindows())
            {
                throw new ArgumentOutOfRangeException("You must supply a certificate file instead of a thumbprint when using a non-Windows operating system.");
            }
            if (PfxCertificate is not null)
            {
                ThrowIfMissing(PfxCertificate, "Could not find the certificate file");
                cert = new X509Certificate2(PfxCertificate);
            }
            else if (Thumbprint is not null)
            {
                cert = CertificateStoreHelper.LookupCertificate(Thumbprint, StoreName, StoreLocation);
            }
            else
            {
                string insert = OperatingSystem.IsWindows() ? " or thumbprint" : string.Empty;
                throw new ArgumentNullException($"You must specify a certificate file{insert} to sign with.");
            }

            return cert;
        }

        /// <summary>
        /// Usage string for certificate choices depending on operating system
        /// </summary>
        private static readonly string certBlock = OperatingSystem.IsWindows() ? @"
    PfxCertificate / pfx: A path to a private key certificate file (.pfx) to sign with.
    --OR--
    Thumbprint / th: The SHA1 thumbprint of a certificate in the Windows local certificate store to sign the file with." + StoreUsageString + @"

    X509RootFiles / ec: Optional. A comma-separated list of private key certificate files (.p7b) to attempt to chain the certificate to.
        Do not use with store certificates."
            : @"
    PfxCertificate / pfx: Required. A path to a private key certificate file (.pfx) to sign with.

    X509RootFiles / ec: Optional. A comma-separated list of private key certificate files (.cer or .p7b) to attempt to chain the certificate to.";


        /// <summary>
        /// Command line usage specific to the Sign command.
        /// </summary>
        public static readonly new string UsageString = BaseUsageString + @"
Sign options:
    Payload / p: Path to the file whose content will be signed.

    SignatureFile / sf: Optional. The file path to write the Cose signature to. Default value is
             For detached: [payload file].cose, or
             For embedded: [payload file].csm

    EmbedPayload / ep: Optional. If true, encrypts and embeds a copy of the payload in the in Cose signature file.
        Default behavior is 'detached signing', where the signature is in a separate file from the payload.
        Note that embed-signed files are not readable by standard text editors.
" + certBlock;
    }
}
