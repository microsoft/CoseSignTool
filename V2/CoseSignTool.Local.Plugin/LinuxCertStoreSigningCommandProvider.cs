// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing by searching Linux/macOS certificate store paths by thumbprint.
/// </summary>
public class LinuxCertStoreSigningCommandProvider : ISigningCommandProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Command metadata
        public static readonly string CommandNameValue = "sign-certstore";
        public static readonly string CommandDescriptionValue = "Sign a payload by searching system certificate store paths by thumbprint";
        public static readonly string ExampleUsageValue = "--thumbprint ABC123";

        // Option names
        public static readonly string OptionNameThumbprint = "--thumbprint";
        public static readonly string OptionNameStorePaths = "--store-paths";

        // Option descriptions
        public static readonly string DescriptionThumbprint = "Certificate thumbprint (hex string) to search in system certificate paths";
        public static readonly string DescriptionStorePaths = "Custom certificate store search paths. Defaults: /etc/ssl/certs, /etc/pki/tls/certs, ~/.certs";

        // Dictionary keys (internal)
        public static readonly string KeyThumbprint = "thumbprint";
        public static readonly string KeyStorePaths = "store-paths";

        // Error messages
        public static readonly string ErrorThumbprintRequired = "Thumbprint is required";

        // Metadata keys and values
        public static readonly string MetaKeyCertSource = "Certificate Source";
        public static readonly string MetaKeyCertSubject = "Certificate Subject";
        public static readonly string MetaKeyCertThumbprint = "Certificate Thumbprint";
        public static readonly string MetaValueLinuxCertStore = "Linux certificate store";
        public static readonly string MetaValueUnknown = "Unknown";
    }

    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    public string CommandName => ClassStrings.CommandNameValue;

    public string CommandDescription => ClassStrings.CommandDescriptionValue;

    public string ExampleUsage => ClassStrings.ExampleUsageValue;

    public void AddCommandOptions(Command command)
    {
        var thumbprintOption = new Option<string>(
            name: ClassStrings.OptionNameThumbprint,
            description: ClassStrings.DescriptionThumbprint)
        {
            IsRequired = true
        };

        var storePathsOption = new Option<string[]?>(
            name: ClassStrings.OptionNameStorePaths,
            description: ClassStrings.DescriptionStorePaths);

        command.AddOption(thumbprintOption);
        command.AddOption(storePathsOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var thumbprint = options[ClassStrings.KeyThumbprint] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorThumbprintRequired);

        var storePaths = options.TryGetValue(ClassStrings.KeyStorePaths, out var paths) ? paths as string[] : null;
        var searchPaths = storePaths?.AsEnumerable() ?? LinuxCertificateStoreCertificateSource.DefaultCertificateStorePaths;

        // Create certificate source by searching system paths
        var certSource = new LinuxCertificateStoreCertificateSource(thumbprint, searchPaths);
        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create signing service
        SigningService = CertificateSigningService.Create(signingCert, chainBuilder);

        return await Task.FromResult(SigningService);
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            [ClassStrings.MetaKeyCertSource] = ClassStrings.MetaValueLinuxCertStore,
            [ClassStrings.MetaKeyCertSubject] = CertificateSubject ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertThumbprint] = CertificateThumbprint ?? ClassStrings.MetaValueUnknown
        };
    }
}