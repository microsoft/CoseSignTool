// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Validators;

using System.Linq;

/// <summary>
/// Validation chain element for verifying a <see cref="CoseSign1Message"/> is signed by a trusted <see cref="X509Certifiate2"/>
/// </summary>
/// <remarks>
/// Creates a new <see cref="X509ChainTrustValidator"/> for validating a given <see cref="CoseSign1Message"/> signing certificate to be trustworthy
/// against the default set of roots on the machine.
/// </remarks>
/// <param name="chainBuilder">The <see cref="ICertificateChainBuilder"/> used to build a chain.</param>
/// <param name="allowUnprotected">True if the UnprotectedHeaders is allowed, False otherwise.</param>
/// <param name="allowUntrusted">True to allow untrusted certificates.</param>
/// <param name="allowOutdated">True to allow signatures with expired certificates to pass validation unless the expired certificate has a lifetime EKU.</param>
public class X509ChainTrustValidator(
    ICertificateChainBuilder chainBuilder,
    bool allowUnprotected = false,
    bool allowUntrusted = false,
    bool allowOutdated = false) : X509Certificate2MessageValidator(allowUnprotected)
{
    private const string LifetimeEkuOidValue = "1.3.6.1.4.1.311.10.3.13";

    #region Public Properties
    /// <summary>
    /// True to allow untrusted certificates to pass validation. This does not apply to self-signed certificates, which trust themselves.
    /// </summary>
    public bool AllowUntrusted { get; set; } = allowUntrusted;

    /// <summary>
    /// The certificate chain builder used to perform chain build operations.
    /// </summary>
    public ICertificateChainBuilder ChainBuilder { get; set; } = chainBuilder;

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
    /// against the default trust list configured for the machine.
    /// </summary>
    /// <param name="revocationMode">The Revocation Mode to be used when performing a revocation check.</param>
    /// <param name="allowUnprotected">True if the UnprotectedHeaders is allowed, False otherwise.</param>
    /// <param name="allowUntrusted">True if allowing untrusted roots.</param>
    public X509ChainTrustValidator(
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        bool allowUnprotected = false,
        bool allowUntrusted = false,
        bool allowOutdated = false):
        this(
            new X509ChainBuilder() { ChainPolicy = new X509ChainPolicy() { RevocationMode = revocationMode } },
            allowUnprotected,
            allowUntrusted,
            allowOutdated)
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
        bool allowUntrusted = false,
        bool allowOutdated = false) :
        this(
            new X509ChainBuilder() { ChainPolicy = new X509ChainPolicy() { RevocationMode = revocationMode } },
            allowUnprotected,
            allowUntrusted,
            allowOutdated)
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
            //Roots.ForEach(c => ChainBuilder.ChainPolicy.ExtraStore.Add(c));

#if NET5_0_OR_GREATER
            if (TrustUserRoots)
            {
                // Trust the user-supplied and system-trusted roots.
                using X509Store x509Store = new(StoreName.Root, StoreLocation.CurrentUser);
                x509Store.Open(OpenFlags.ReadOnly);
                X509CertificateCollection trustAnchors = [.. x509Store.Certificates, .. Roots];
                ChainBuilder.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                ChainBuilder.ChainPolicy.CustomTrustStore.AddRange(trustAnchors);
            }
            else
            {
                ChainBuilder.ChainPolicy.TrustMode = X509ChainTrustMode.System;
                ChainBuilder.ChainPolicy.CustomTrustStore.Clear();
            }
#endif
        }

        if (certChain?.Count > 0)
        {
            ChainBuilder.ChainPolicy.ExtraStore.AddRange(certChain.ToArray());
        }

        if (extraCertificates?.Count > 0)
        {
            ChainBuilder.ChainPolicy.ExtraStore.AddRange(extraCertificates.ToArray());
        }

        // Build the cert chain. If Build succeeds, return success.
        if (ChainBuilder.Build(signingCertificate))
        {
            return new CoseSign1ValidationResult(GetType(), true, "Certificate was Trusted.");
        }

        // If we fail because chain build failed to reach the revocation server, retry in case the server is down.
        if (ChainBuilder.ChainPolicy.RevocationMode != X509RevocationMode.NoCheck)
        {
            int maxAttempts = 3;
            for (int i = 0;
                i < maxAttempts && ChainBuilder.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.RevocationStatusUnknown) != 0);
                i++)
            {
                if (ChainBuilder.Build(signingCertificate))
                {
                    return new CoseSign1ValidationResult(GetType(), true, "Certificate was Trusted.");
                }

                Thread.Sleep(1000);
            }
        }

        // If we're here, chain build failed. We need to filter out the errors we're willing to ignore.
        // This is the result of building the certificate chain.
        CoseSign1ValidationResult baseResult = new (GetType(), false,
            $"[{string.Join("][", ChainBuilder.ChainStatus.Select(cs => cs.StatusInformation + "/n" + cs.Status.ToString() + (int)cs.Status).ToArray())}]",
            ChainBuilder.ChainStatus.Cast<object>().ToList());

        // Ignore failures from untrusted roots or expired certificates if the user tells us to.
        X509ChainStatusFlags flagsToIgnore = X509ChainStatusFlags.NoError;
        flagsToIgnore |= AllowUntrusted ? X509ChainStatusFlags.UntrustedRoot : 0;

        // If we have a valid user-supplied root, consider it trusted. (Not supported by .NET Standard 2.0 so we have to do it ourselves.)
        string chainRootThumb = ChainBuilder.ChainElements.FirstOrDefault(element => element.Subject.Equals(element.Issuer))?.Thumbprint ?? string.Empty;
        bool trustUserRoot = hasRoots && TrustUserRoots && !string.IsNullOrEmpty(chainRootThumb) && Roots!.Any(r => r.Thumbprint == chainRootThumb);
        flagsToIgnore |= trustUserRoot ? X509ChainStatusFlags.UntrustedRoot : 0;

        // If allowOutdated is set and none of the outdated certificates in the chain have a lifetime EKU, ignore NotTimeValid.
        List<X509Certificate2>? outdatedCerts = ChainBuilder.ChainElements?.Where(c => c.NotAfter < DateTime.Now).ToList();
        if (allowOutdated && outdatedCerts is not null && outdatedCerts.Count > 0)
        {
            bool chainHasLifetimeEku = outdatedCerts
                .Any(cert => cert.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                    .Any(extension => extension.EnhancedKeyUsages.OfType<Oid>()
                        .Any(ekuOid => ekuOid.Value == LifetimeEkuOidValue)));

            if (!chainHasLifetimeEku)
            {
                flagsToIgnore |= X509ChainStatusFlags.NotTimeValid;
            }
        }

        // If we only have the allowed chain status messages, return success.
        if (ChainBuilder.ChainStatus.All(st => (st.Status &~ flagsToIgnore) == 0)) // use &~ to mask out UntrustedRoot and NoError
        {
            bool resultUntrusted = ChainBuilder.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.UntrustedRoot));
            bool untrustedAndAllowed = resultUntrusted && AllowUntrusted && !trustUserRoot;
            bool outdatedAndAllowed = ChainBuilder.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.NotTimeValid)) && allowOutdated;

            string message =
                outdatedAndAllowed && untrustedAndAllowed ? "Certificate was allowed because AllowOutdated and AllowUntrusted were both specified." :
                outdatedAndAllowed ? "Certificate was allowed because AllowOutdated was specified." :
                resultUntrusted && trustUserRoot ? "Certificate was Trusted." :
                "Certificate was allowed because AllowUntrusted was specified." ;

            return new CoseSign1ValidationResult(GetType(), true, message);
        }

        // Validation failed.
        return baseResult;
    }
    #endregion
}
