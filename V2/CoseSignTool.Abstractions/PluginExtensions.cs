// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Contains all extension points a plugin can contribute to CoseSignTool.
/// Plugins return this model from GetExtensions() with only the capabilities they provide.
/// </summary>
/// <remarks>
/// This model-based approach allows adding new extension points without breaking existing plugins.
/// Plugins only need to populate the collections they support; empty collections are the default.
/// </remarks>
public sealed class PluginExtensions
{
    /// <summary>
    /// Creates an empty extensions instance (plugin provides no extensions).
    /// </summary>
    public PluginExtensions()
        : this([], [], [], null, null, null)
    {
    }

    /// <summary>
    /// Creates a new PluginExtensions instance with the specified providers.
    /// </summary>
    /// <param name="signingCommandProviders">The signing command providers offered by the plugin.</param>
    /// <param name="verificationProviders">The verification providers offered by the plugin.</param>
    /// <param name="transparencyProviders">The transparency providers offered by the plugin.</param>
    /// <param name="signingRootProviders">The signing root providers offered by the plugin.</param>
    /// <param name="signingMaterialProviders">The signing material providers offered by the plugin.</param>
    /// <param name="certificateSigningMaterialProviders">Certificate signing material providers offered by the plugin.</param>
    public PluginExtensions(
        IEnumerable<ISigningCommandProvider> signingCommandProviders,
        IEnumerable<IVerificationProvider> verificationProviders,
        IEnumerable<ITransparencyProviderContributor> transparencyProviders,
        IEnumerable<ISigningRootProvider>? signingRootProviders = null,
        IEnumerable<ISigningMaterialProvider>? signingMaterialProviders = null,
        IEnumerable<ICertificateSigningMaterialProvider>? certificateSigningMaterialProviders = null)
    {
        SigningCommandProviders = signingCommandProviders ?? [];
        VerificationProviders = verificationProviders ?? [];
        TransparencyProviders = transparencyProviders ?? [];
        SigningRootProviders = signingRootProviders ?? [];
        SigningMaterialProviders = signingMaterialProviders ?? [];
        CertificateSigningMaterialProviders = certificateSigningMaterialProviders ?? [];
    }

    /// <summary>
    /// Gets the signing command providers offered by this plugin.
    /// </summary>
    public IEnumerable<ISigningCommandProvider> SigningCommandProviders { get; }

    /// <summary>
    /// Gets the verification providers offered by this plugin.
    /// </summary>
    public IEnumerable<IVerificationProvider> VerificationProviders { get; }

    /// <summary>
    /// Gets the transparency providers offered by this plugin.
    /// </summary>
    public IEnumerable<ITransparencyProviderContributor> TransparencyProviders { get; }

    /// <summary>
    /// Gets the signing root providers offered by this plugin.
    /// </summary>
    public IEnumerable<ISigningRootProvider> SigningRootProviders { get; }

    /// <summary>
    /// Gets the signing material providers offered by this plugin.
    /// </summary>
    public IEnumerable<ISigningMaterialProvider> SigningMaterialProviders { get; }

    /// <summary>
    /// Gets certificate signing material providers offered by this plugin.
    /// These will be bound under the X.509 signing root.
    /// </summary>
    public IEnumerable<ICertificateSigningMaterialProvider> CertificateSigningMaterialProviders { get; }

    /// <summary>
    /// Creates an empty extensions instance (plugin provides no extensions).
    /// </summary>
    public static PluginExtensions None => new();
}