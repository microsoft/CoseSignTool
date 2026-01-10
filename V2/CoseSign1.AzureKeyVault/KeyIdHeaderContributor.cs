// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault;

using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Abstractions;

/// <summary>
/// Header contributor that adds the key identification (kid) header (label 4) to protected headers.
/// This enables verification scenarios where the public key can be retrieved from Azure Key Vault
/// using the embedded key URI.
/// </summary>
/// <remarks>
/// <para>
/// Per RFC 9052 Section 3.1, the <c>kid</c> (Key ID) header identifies which key was used
/// to create the signature. For Azure Key Vault keys, this is the full Key Vault key URI
/// (e.g., <c>https://myvault.vault.azure.net/keys/mykey/abc123</c>).
/// </para>
/// <para>
/// This contributor is automatically used by <see cref="AzureKeyVaultSigningService"/> to embed
/// the key URI in signatures. During verification, the <c>kid</c> header can be extracted and
/// used to fetch the public key from Key Vault for signature verification.
/// </para>
/// <para>
/// <strong>Header Labels:</strong>
/// <list type="bullet">
/// <item><description><c>kid</c> (label 4): Key Vault key URI with version</description></item>
/// </list>
/// </para>
/// </remarks>
public sealed class KeyIdHeaderContributor : IHeaderContributor
{
    /// <summary>
    /// The COSE header label for key ID (kid) per RFC 9052.
    /// </summary>
    public static readonly CoseHeaderLabel KidHeaderLabel = new(4);

    /// <summary>
    /// Gets the Key ID (kid) value that will be added to the headers.
    /// This is typically the full Key Vault key URI.
    /// </summary>
    public string KeyId { get; }

    /// <summary>
    /// Gets a value indicating whether the key is HSM-protected.
    /// </summary>
    public bool IsHsmProtected { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyIdHeaderContributor"/> class.
    /// </summary>
    /// <param name="keyId">The key ID (typically Key Vault key URI).</param>
    /// <param name="isHsmProtected">Whether the key is HSM-protected.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="keyId"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="keyId"/> is empty or whitespace.</exception>
    public KeyIdHeaderContributor(string keyId, bool isHsmProtected = false)
    {
        Guard.ThrowIfNull(keyId);
        Guard.ThrowIfNullOrWhiteSpace(keyId);
        KeyId = keyId;
        IsHsmProtected = isHsmProtected;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Uses Replace strategy to update the kid header if it already exists.
    /// This allows the contributor to override any default kid values.
    /// </remarks>
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    /// <inheritdoc/>
    /// <remarks>
    /// Adds the <c>kid</c> (Key ID) header to protected headers with the Key Vault key URI.
    /// The kid is added to protected headers (not unprotected) to prevent tampering.
    /// </remarks>
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // RFC 9052 requires "kid" (label 4) to be a bstr.
        var kidValue = CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(KeyId));

        if (headers.ContainsKey(KidHeaderLabel))
        {
            headers[KidHeaderLabel] = kidValue;
        }
        else
        {
            headers.Add(KidHeaderLabel, kidValue);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Does not contribute any unprotected headers.
    /// The key ID must be in protected headers to prevent tampering.
    /// </remarks>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // kid is only added to protected headers to prevent tampering
    }
}
