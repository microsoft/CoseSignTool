// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Validators;

/// <summary>
/// Validation chain element for verifying a <see cref="CoseSign1Message"/> is signed by a trusted <see cref="X509Certifiate2"/>
/// </summary>
public class X509ChainTrustValidator : X509Certificate2MessageValidator
{
    #region Public Properties
    /// <summary>
    /// True to allow untrusted certificates to pass validation. This does not apply to self-signed certificates, which trust themselves.
    /// </summary>
    public bool AllowUntrusted { get; set; }

    /// <summary>
    /// The certificate chain builder used to perform chain build operations.
    /// </summary>
    public ICertificateChainBuilder ChainBuilder { get; set; }

    /// <summary>
    /// An optional list of user specified roots to trust. If unspecified, the default roots on the machine will be used instead.
    /// </summary>
    public List<X509Certificate2>? Roots { get; set; }

    /// <summary>
    /// An optional set of X509ChainStatusFlags that should be allowed without failing validation when building the certificate chain.
    /// </summary>
    public X509ChainStatusFlags? AllowedFlags { get; set; }

    /// <summary>
    /// Assumes that user-supplied roots are trusted. True by default.
    /// </summary>
    public bool TrustUserRoots { get; set; } = true;
    #endregion

    #region Constructors
    /// <summary>
    /// Creates a new <see cref="X509ChainTrustValidator"/> for validating a given <see cref="CoseSign1Message"/> signing certificate to be trustworthy
    /// against the default set of roots on the machine.
    /// </summary>
    /// <param name="chainBuilder">The <see cref="ICertificateChainBuilder"/> used to build a chain.</param>
    /// <param name="allowUnprotected">True if the UnprotectedHeaders is allowed, False otherwise.</param>
    /// <param name="allowUntrusted">True to allow untrusted certificates.</param>
    public X509ChainTrustValidator(
        ICertificateChainBuilder chainBuilder,
        bool allowUnprotected = false,
        bool allowUntrusted = false) : base(allowUnprotected)
    {
        ChainBuilder = chainBuilder;
        AllowUntrusted = allowUntrusted;
    }

    /// <summary>
    /// Creates a new <see cref="X509ChainTrustValidator"/> for validating a given <see cref="CoseSign1Message"/> signing certificate to be trustworthy
    /// against the default trust list configured for the machine.
    /// </summary>
    /// <param name="revocationMode">The Revocation Mode to be used when performing a revocation check.</param>
    /// <param name="allowUnprotected">True if the UnprotectedHeaders is allowed, False otherwise.</param>
    /// <param name="allowUntrusted">True if allowing untrusted roots.</param>
    public X509ChainTrustValidator(
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        bool allowUnprotected = false,
        bool allowUntrusted = false) :
        this(
            new X509ChainBuilder() { ChainPolicy = new X509ChainPolicy() { RevocationMode = revocationMode } },
            allowUnprotected,
            allowUntrusted)
    {
    }

    /// <summary>
    /// Creates a new <see cref="X509ChainTrustValidator"/> for validating a given <see cref="CoseSign1Message"/> signing certificate to be trustworthy
    /// against a specified set of roots
    /// </summary>
    /// <param name="roots">The specified set of roots that the user wants to be validated against.</param>
    /// <param name="revocationMode">The Revocation Mode to be used when performing a revocation check.</param>
    /// <param name="allowUnprotected">True if the UnprotectedHeaders is allowed, False otherwise.</param>
    /// <param name="allowUntrusted">True if allowing untrusted certificates.</param>
    public X509ChainTrustValidator(
        List<X509Certificate2>? roots,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        bool allowUnprotected = false,
        bool allowUntrusted = false) :
        this(
            new X509ChainBuilder() { ChainPolicy = new X509ChainPolicy() { RevocationMode = revocationMode } },
            allowUnprotected,
            allowUntrusted)
    {
        Roots = roots;
    }
    #endregion

    #region Overrides
    /// <inheritdoc/>
    protected override CoseSign1ValidationResult ValidateCertificate(
        X509Certificate2 signingCertificate,
        List<X509Certificate2>? certChain,
        List<X509Certificate2>? extraCertificates)
    {

        // If there are user-supplied roots, add them to the ExtraCerts collection.
        bool hasRoots = false;
        if (Roots?.Count > 0)
        {
            hasRoots = true;
            ChainBuilder.ChainPolicy.ExtraStore.Clear();
            Roots.ForEach(c => ChainBuilder.ChainPolicy.ExtraStore.Add(c));
        }

        // Build the cert chain. If Build succeeds, return success.
        if (ChainBuilder.Build(signingCertificate))
        {
            return new CoseSign1ValidationResult(GetType(), true, "Certificate was Trusted.");
        }

        // Chain build failed, but if the only failure is Untrusted Root we may still pass.
        if (ChainBuilder.ChainStatus.All(st => st.Status.HasFlag(X509ChainStatusFlags.UntrustedRoot) || st.Status.HasFlag(X509ChainStatusFlags.NoError)))
        {
            // We can't specify an alternative root in .netstandard 2.1, so our work-around is to consider any user-supplied roots trusted.
            // This logic should be replaced once the library updates to a .NET Standard version that supports assigning arbitrary root trust like .NET 7 does.
            if (hasRoots && TrustUserRoots && Roots.Any(r => r.Thumbprint == ChainBuilder.ChainElements.First().Thumbprint))
            {
                // The root of the chain is one of the user-supplied roots, so return success.
                return new CoseSign1ValidationResult(GetType(), true, "Certificate was Trusted.");
            }

            if (AllowUntrusted)
            {
                // The root was untrusted but the user allowed it.
                return new CoseSign1ValidationResult(GetType(), true, "Certificate was allowed because AllowUntrusted was specified.");
            }
        }

        // Validation failed.
        return new CoseSign1ValidationResult(GetType(), false,
            $"[{string.Join("][", ChainBuilder.ChainStatus.Select(cs => cs.StatusInformation).ToArray())}]",
            ChainBuilder.ChainStatus.Cast<object>().ToList());
    }
    #endregion
}