// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Logging;

/// <summary>
/// Command provider for signing with Windows certificate store.
/// </summary>
public class WindowsCertStoreSigningCommandProvider : ISigningCommandProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Command metadata
        public static readonly string CommandNameValue = "sign-certstore";
        public static readonly string CommandDescriptionValue = "Sign a payload with a certificate from Windows certificate store";
        public static readonly string ExampleUsageValue = "--thumbprint ABC123";

        // Option names
        public static readonly string OptionNameThumbprint = "--thumbprint";
        public static readonly string OptionNameStoreLocation = "--store-location";
        public static readonly string OptionNameStoreName = "--store-name";

        // Option descriptions
        public static readonly string DescriptionThumbprint = "Certificate thumbprint (hex string) to find in the certificate store";
        public static readonly string DescriptionStoreLocation = "Certificate store location (CurrentUser or LocalMachine)";
        public static readonly string DescriptionStoreName = "Certificate store name (My, Root, CA, etc.)";

        // Default values
        public static readonly string DefaultStoreLocation = "CurrentUser";
        public static readonly string DefaultStoreName = "My";

        // Dictionary keys (internal)
        public static readonly string KeyThumbprint = "thumbprint";
        public static readonly string KeyStoreLocation = "store-location";
        public static readonly string KeyStoreName = "store-name";
        public static readonly string KeyLoggerFactory = "__loggerFactory";

        // Error messages
        public static readonly string ErrorThumbprintRequired = "Thumbprint is required";

        // Metadata keys and values
        public static readonly string MetaKeyCertSource = "Certificate Source";
        public static readonly string MetaKeyCertSubject = "Certificate Subject";
        public static readonly string MetaKeyCertThumbprint = "Certificate Thumbprint";
        public static readonly string MetaValueWinCertStore = "Windows certificate store";
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
        var thumbprintOption = new Option<string>(
            name: ClassStrings.OptionNameThumbprint,
            description: ClassStrings.DescriptionThumbprint)
        {
            IsRequired = true
        };

        var storeLocationOption = new Option<string>(
            name: ClassStrings.OptionNameStoreLocation,
            getDefaultValue: () => ClassStrings.DefaultStoreLocation,
            description: ClassStrings.DescriptionStoreLocation);

        var storeNameOption = new Option<string>(
            name: ClassStrings.OptionNameStoreName,
            getDefaultValue: () => ClassStrings.DefaultStoreName,
            description: ClassStrings.DescriptionStoreName);

        command.AddOption(thumbprintOption);
        command.AddOption(storeLocationOption);
        command.AddOption(storeNameOption);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Required options are missing.</exception>
    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var thumbprint = options[ClassStrings.KeyThumbprint] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorThumbprintRequired);
        var storeLocation = options.TryGetValue(ClassStrings.KeyStoreLocation, out var loc) ? loc as string ?? ClassStrings.DefaultStoreLocation : ClassStrings.DefaultStoreLocation;
        var storeName = options.TryGetValue(ClassStrings.KeyStoreName, out var name) ? name as string ?? ClassStrings.DefaultStoreName : ClassStrings.DefaultStoreName;

        // Get logger factory if provided
        var loggerFactory = options.TryGetValue(ClassStrings.KeyLoggerFactory, out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<WindowsCertificateStoreCertificateSource>();

        // Parse store location and name
        var storeLocationEnum = Enum.Parse<StoreLocation>(storeLocation, ignoreCase: true);
        var storeNameEnum = Enum.Parse<StoreName>(storeName, ignoreCase: true);

        // Create certificate source with logging
        var certSource = new WindowsCertificateStoreCertificateSource(
            thumbprint,
            storeNameEnum,
            storeLocationEnum,
            logger: logger);

        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create logger for signing service
        var signingServiceLogger = loggerFactory?.CreateLogger<CertificateSigningService>();

        // Create signing service
        SigningService = CertificateSigningService.Create(signingCert, chainBuilder, signingServiceLogger);

        return await Task.FromResult(SigningService);
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            [ClassStrings.MetaKeyCertSource] = ClassStrings.MetaValueWinCertStore,
            [ClassStrings.MetaKeyCertSubject] = CertificateSubject ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertThumbprint] = CertificateThumbprint ?? ClassStrings.MetaValueUnknown
        };
    }
}