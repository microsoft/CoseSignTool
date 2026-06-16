// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Optional capability interface implemented by <see cref="ICoseSigningKeyProvider"/> implementations
/// that support toggling SCITT (Supply Chain Integrity, Transparency, and Trust) compliance behavior.
/// </summary>
/// <remarks>
/// <para>
/// Hosts that need to enable or disable automatic CWT (CBOR Web Token) claim emission on a
/// signing-key provider should test for this interface rather than depending on a specific concrete
/// type. This keeps the cross-boundary contract in <c>CoseSign1.Abstractions</c>, allowing
/// implementing assemblies (e.g. <c>CoseSign1.Certificates</c>) to remain plugin-local in
/// host/plugin <see cref="System.Runtime.Loader.AssemblyLoadContext"/> isolation scenarios without
/// triggering type-identity mismatches.
/// </para>
/// <para>
/// Example host pattern:
/// <code>
/// ICoseSigningKeyProvider provider = plugin.CreateProvider(configuration);
/// if (provider is ISupportsScittCompliance scittProvider)
/// {
///     scittProvider.EnableScittCompliance = enableScittCompliance;
/// }
/// </code>
/// </para>
/// </remarks>
public interface ISupportsScittCompliance
{
    /// <summary>
    /// Gets or sets a value indicating whether SCITT-compliant CWT claims (issuer and subject) are
    /// automatically added to signatures produced by this provider.
    /// </summary>
    /// <remarks>
    /// Implementations should default this to <c>true</c> when SCITT compliance is the expected
    /// behavior for the provider. Setting to <c>false</c> suppresses default-claim emission;
    /// user-supplied CWT claims attached via header extenders remain unaffected.
    /// </remarks>
    bool EnableScittCompliance { get; set; }
}
