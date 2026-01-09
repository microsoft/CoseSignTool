// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;

/// <summary>
/// Command provider for signing with PEM certificate and key files on Linux/macOS.
/// </summary>
public class PemSigningCommandProvider : ISigningCommandProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Command metadata
        public static readonly string CommandNameValue = "sign-pem";
        public static readonly string CommandDescriptionValue = "Sign a payload with PEM certificate and private key files";
        public static readonly string ExampleUsageValue = "--cert-file cert.pem --key-file key.pem";

        // Option names
        public static readonly string OptionNameCertFile = "--cert-file";
        public static readonly string OptionNameKeyFile = "--key-file";

        // Option descriptions
        public static readonly string DescriptionCertFile = "Path to the certificate file (.pem, .crt)";
        public static readonly string DescriptionKeyFile = "Path to the private key file (.key, .pem)";

        // Dictionary keys (internal)
        public static readonly string KeyCertFile = "cert-file";
        public static readonly string KeyKeyFile = "key-file";

        // Error messages
        public static readonly string ErrorCertRequired = "Certificate file is required";
        public static readonly string ErrorKeyRequired = "Private key file is required";
        public static readonly string ErrorCertNotFound = "Certificate file not found: {0}";
        public static readonly string ErrorKeyNotFound = "Private key file not found: {0}";

        // Metadata keys and values
        public static readonly string MetaKeyCertSource = "Certificate Source";
        public static readonly string MetaKeyCertSubject = "Certificate Subject";
        public static readonly string MetaKeyCertThumbprint = "Certificate Thumbprint";
        public static readonly string MetaValuePemFiles = "PEM files";
        public static readonly string MetaValueUnknown = "Unknown";
    }

    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    /// <inheritdoc/>
    public string CommandName => ClassStrings.CommandNameValue;

    /// <inheritdoc/>
    public string CommandDescription => ClassStrings.CommandDescriptionValue;

    /// <inheritdoc/>
    public string ExampleUsage => ClassStrings.ExampleUsageValue;

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var certFileOption = new Option<FileInfo>(
            name: ClassStrings.OptionNameCertFile,
            description: ClassStrings.DescriptionCertFile)
        {
            IsRequired = true
        };

        var keyFileOption = new Option<FileInfo>(
            name: ClassStrings.OptionNameKeyFile,
            description: ClassStrings.DescriptionKeyFile)
        {
            IsRequired = true
        };

        command.AddOption(certFileOption);
        command.AddOption(keyFileOption);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Required options are missing.</exception>
    /// <exception cref="FileNotFoundException">The certificate or key file does not exist.</exception>
    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var certFile = options[ClassStrings.KeyCertFile] as FileInfo
            ?? throw new InvalidOperationException(ClassStrings.ErrorCertRequired);
        var keyFile = options[ClassStrings.KeyKeyFile] as FileInfo
            ?? throw new InvalidOperationException(ClassStrings.ErrorKeyRequired);

        if (!certFile.Exists)
        {
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorCertNotFound, certFile.FullName));
        }

        if (!keyFile.Exists)
        {
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorKeyNotFound, keyFile.FullName));
        }

        // Create certificate source from PEM files
        var certSource = new LinuxCertificateStoreCertificateSource(
            certFile.FullName,
            keyFile.FullName);

        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create signing service
        SigningService = CertificateSigningService.Create(signingCert, chainBuilder);

        return await Task.FromResult(SigningService);
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            [ClassStrings.MetaKeyCertSource] = ClassStrings.MetaValuePemFiles,
            [ClassStrings.MetaKeyCertSubject] = CertificateSubject ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertThumbprint] = CertificateThumbprint ?? ClassStrings.MetaValueUnknown
        };
    }
}