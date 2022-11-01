// ----------------------------------------------------------------------------------------
// <copyright file="ValidateCommand.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignTool
{
    using CoseX509;
    using Microsoft.Extensions.Configuration.CommandLine;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public sealed class ValidateCommand : CoseCommand
    {
        /// <summary>
        /// A map of command line options to their abbreviated alaises.
        /// </summary>
        public static readonly Dictionary<string, string> Options = new()
        {
            ["-X509RootFiles"] = "X509RootFiles",
            ["-Thumbprints"] = "Thumbprints",
            ["-RevocationMode"] = "RevocationMode",
            ["-CommonName"] = "CommonName",
            ["-SavePayloadTo"] = "SavePayloadTo",
            ["-x5"] = "X509RootFiles",
            ["-xr"] = "X509RootFiles",
            ["-th"] = "Thumbprints",
            ["-rv"] = "RevocationMode",
            ["-cn"] = "CommonName",
            ["-sp"] = "SavePayloadTo",
        };

        #region Public properties
        /// <summary>
        /// One or more public key certificate files (.cer or .p7b) to attempt to chain the COSE signature to.
        /// These certificates do not have to be trusted on the local machine.
        /// </summary>
        public string[] X509RootFiles { get; set; }

        /// <summary>
        /// The thumbprints of one or more installed certificates in the Windows Certificate Store to attempt to chain the COSE signature to.
        /// These certificates do not have to be trusted on the local machine.
        /// </summary>
        public string[] Thumbprints { get; set; }

        /// <summary>
        /// The revocation mode to use when checking for expired or revoked certificates.
        /// Default is X509RevocationMode.Online.
        /// </summary>
        public X509RevocationMode RevocationMode { get; set; }

        /// <summary>
        /// Requires that the signing certificate must match a specific Certificate Common Name.
        /// </summary>
        [DefaultValue(null)]
        public string CommonName { get; set; }

        /// <summary>
        /// A file path to write a copy of the original payload to.
        /// By default, no file is created.
        /// </summary>
        public string SavePayloadTo { get; set; }
        #endregion

        /// <summary>
        /// For test use only.
        /// </summary>
        internal ValidateCommand() { }

        /// <summary>
        /// Creates a ValidateCommand instance and sets its properties with a CommandLineConfigurationProvider.
        /// </summary>
        /// <param name="provider">A CommandLineConfigurationProvider that has loaded the command line arguments.</param>
        public ValidateCommand(CommandLineConfigurationProvider provider)
        {
            ApplyOptions(provider);

            if (!X509RootFiles.Any() && !Thumbprints.Any())
            {
                string insert = OperatingSystem.IsWindows() ? "thumbprint or " : string.Empty;
                throw new ArgumentNullException($"You must specify at least one {insert}x509 root file to chain the signature to.");
            }

            ThrowIfNullOrEmpty(SignatureFile, nameof(SignatureFile));
            ThrowIfMissing(SignatureFile, "Could not find the signed file");
        }

        /// <summary>
        /// Validates a Cose signed file.
        /// </summary>
        /// <returns>An exit code indicating success or failure.</returns>
        public override ExitCode Run()
        {
            // Declare these as bools so they are easier to keep track of
            bool embedSigned = string.IsNullOrEmpty(Payload);
            bool detachSigned = !embedSigned;

            if (detachSigned)
            {
                if (SavePayloadTo != null)
                {
                    throw new ArgumentException("SavePayloadTo can only be set when Payload is not set.");
                }
                ThrowIfMissing(Payload, "Could not find the external Payload file");
            }

            // Load root certs from file
            var rootCerts = LoadRootCerts(X509RootFiles);

            // Load root certs from store
            var storeCerts = CertificateStoreHelper.LookupCertificates(Thumbprints.ToList(), StoreName, StoreLocation);
            rootCerts.AddRange(storeCerts);

            try
            {
                if (SavePayloadTo is not null) // embed-signed and retrieving content...
                {
                    byte[] payloadBytes = CoseParser.GetPayload(SignatureFile, rootCerts, RevocationMode, CommonName);
                    File.WriteAllBytes(SavePayloadTo, payloadBytes);
                }
                else if (embedSigned) // but not retrieving content...
                {
                    CoseParser.Validate(SignatureFile, rootCerts, RevocationMode, CommonName);
                }
                else // detach signed, so no content to retrieve.
                {
                    CoseParser.Validate(SignatureFile, Payload, rootCerts, RevocationMode, CommonName);
                }

                return ExitCode.Success;
            }
            catch (CryptographicException ex)
            {
                CoseSignTool.Fail(ExitCode.CertificateLoadFailure, $"Certificate could not be loaded: {ex.Message}");
            }
            catch (CoseX509FormatException ex)
            {
                CoseSignTool.Fail(ExitCode.CertificateLoadFailure, $"Certificate chain did not meet COSE formatting requirements: {ex.Message}");
            }
            catch (CoseValidationException ex)
            {
                CoseSignTool.Fail(ExitCode.CertificateLoadFailure, ex.Message);
            }

            return ExitCode.CertificateLoadFailure;
        }

        //<inheritdoc />
        protected internal override void ApplyOptions(CommandLineConfigurationProvider provider)
        {
            X509RootFiles = GetOptionArray(provider, "X509RootFiles");
            Thumbprints = GetOptionArray(provider, "Thumbprints");
            RevocationMode = Enum.Parse<X509RevocationMode>(GetOptionString(provider, "RevocationMode", "online"), true);
            CommonName = GetOptionString(provider, "CommonName");
            SavePayloadTo = GetOptionString(provider, "SavePayloadTo");
            base.ApplyOptions(provider);
        }

        // Load public key certificates from file
        private static List<X509Certificate2> LoadRootCerts(string[] X509RootFiles)
        {
            var rootCerts = new List<X509Certificate2>();
            foreach (var rootFile in X509RootFiles)
            {
                ThrowIfMissing(rootFile, "Could not find one of the the X509RootFiles entries");

                switch (Path.GetExtension(rootFile).ToLowerInvariant())
                {
                    case ".p7b":
                        var certCollection = new X509Certificate2Collection();
                        certCollection.Import(rootFile);
                        rootCerts.AddRange(certCollection);
                        break;
                    case ".cer":
                        var rootCert = new X509Certificate2(rootFile);
                        rootCerts.Add(rootCert);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException($"Unsupported certificate container type {rootFile}");
                }
            }

            return rootCerts;
        }

        /// <summary>
        /// Usage string for certificate choices depending on operating system
        /// </summary>
        private static string certBlock = OperatingSystem.IsWindows() ? @"
    X509RootFiles / xr: A comma-separated list of public key certificate files (.cer or .p7b) to attempt to chain
        the COSE signature to.
    --OR--
    Thumbprints / th: A comma-separated list of SHA1 thumbprints of one or more certificates in the Windows local
        certificate store to attempt to chain the certificate on the COSE signature to." + StoreUsageString
            : @"
    X509RootFiles / xr: Required. A comma-separated list of public key certificate files (.cer or .p7b) to attempt
        to chain the COSE signature to.";


        internal static new string UsageString = $@"{BaseUsageString}
Validate options:
    SignatureFile / sf: Required. The file containing the COSE signature.
        If embedded, this file also includes the encoded payload.

    Payload / p: Path to the original source file that was detach-signed. Do not use for embedded signatures.
" + certBlock + @"

    RevocationMode / rm: The method to check for certificate revocation.
        Valid values: Online, Offline, NoCheck
        Default value: Online

    CommonName / cn: Specifies a certificate Common Name that the signing certificate must match to pass validation.

    SavePayload / sp: Writes the payload of an embed-signed file to the specified file path.
        For embedded signatures only.";
    }
}
