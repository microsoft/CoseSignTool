// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Builder for configuring certificate trust-pack registrations.
/// </summary>
public sealed class CertificateTrustBuilder
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Space = " ";

        public const string ErrorTrustSourceAlreadyConfigured =
            "A certificate trust source has already been configured. Only one trust source may be selected.";

        public const string ErrorNoTrustSourceConfigured =
            "No certificate trust source configured. Call UseSystemTrust(), UseCustomRootTrust(...), or UseEmbeddedChainOnly().";

        public const string ErrorNoIdentityConstraintsConfigured =
            "No certificate identity allow-list configured. Configure thumbprints or subject/issuer patterns, or do not enable identity pinning.";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateTrustBuilder"/> class.
    /// </summary>
    public CertificateTrustBuilder()
    {
    }

    /// <summary>
    /// Gets the configured options for certificate trust.
    /// </summary>
    public CertificateTrustOptions Options { get; } = new();

    /// <summary>
    /// Enables certificate identity pinning (allow-list enforcement).
    /// </summary>
    /// <param name="configure">The callback used to configure identity pinning strategies.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when identity pinning is enabled but no strategies are configured.</exception>
    public CertificateTrustBuilder EnableCertificateIdentityPinning(Action<CertificateIdentityPinningBuilder> configure)
    {
        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        Options.IdentityPinningEnabled = true;

        var builder = new CertificateIdentityPinningBuilder(Options);
        configure(builder);

        if (Options.AllowedThumbprints.Count == 0 && Options.AllowedSubjectIssuerPatterns.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoIdentityConstraintsConfigured);
        }

        return this;
    }

    /// <summary>
    /// Configures the pack to use system trust roots.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public CertificateTrustBuilder UseSystemTrust()
    {
        Options.EnsureTrustSource(CertificateTrustSourceKind.System);
        return this;
    }

    /// <summary>
    /// Configures the pack to trust only the chain embedded in the COSE message (x5chain),
    /// allowing unknown roots (typically paired with identity pinning).
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public CertificateTrustBuilder UseEmbeddedChainOnly()
    {
        Options.EnsureTrustSource(CertificateTrustSourceKind.EmbeddedChainOnly);
        return this;
    }

    /// <summary>
    /// Configures the pack to use a custom root store.
    /// </summary>
    /// <param name="customRoots">The custom root certificates to trust.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="customRoots"/> is null.</exception>
    public CertificateTrustBuilder UseCustomRootTrust(X509Certificate2Collection customRoots)
    {
        if (customRoots == null)
        {
            throw new ArgumentNullException(nameof(customRoots));
        }

        foreach (var root in customRoots)
        {
            Options.AddCustomRoot(root);
        }

        return this;
    }

    /// <summary>
    /// Configures the revocation mode used during certificate chain operations.
    /// </summary>
    /// <param name="mode">The revocation mode to use.</param>
    /// <returns>The same builder instance.</returns>
    public CertificateTrustBuilder WithRevocationMode(X509RevocationMode mode)
    {
        Options.RevocationMode = mode;
        return this;
    }

    /// <summary>
    /// Configures the revocation scope used during chain building.
    /// </summary>
    /// <param name="flag">The revocation flag to use.</param>
    /// <returns>The same builder instance.</returns>
    public CertificateTrustBuilder WithRevocationFlag(X509RevocationFlag flag)
    {
        Options.RevocationFlag = flag;
        return this;
    }

    /// <summary>
    /// Configures verification flags used during chain building.
    /// </summary>
    /// <param name="flags">The verification flags to use.</param>
    /// <returns>The same builder instance.</returns>
    public CertificateTrustBuilder WithVerificationFlags(X509VerificationFlags flags)
    {
        Options.VerificationFlags = flags;
        return this;
    }

    /// <summary>
    /// Options used by the certificate trust pack at evaluation time.
    /// </summary>
    /// <remarks>
    /// This type is typically constructed and configured via <see cref="CertificateTrustBuilder"/>.
    /// </remarks>
    public sealed class CertificateTrustOptions
    {
        internal CertificateTrustSourceKind SourceKind { get; private set; } = CertificateTrustSourceKind.None;

        internal X509Certificate2Collection CustomTrustRoots { get; } = new();

        internal IList<string> AllowedThumbprints { get; } = new List<string>();

        internal IList<CertificateIdentityPattern> AllowedSubjectIssuerPatterns { get; } = new List<CertificateIdentityPattern>();

        internal bool IdentityPinningEnabled { get; set; }

        internal X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

        internal X509RevocationFlag RevocationFlag { get; set; } = X509RevocationFlag.ExcludeRoot;

        internal X509VerificationFlags VerificationFlags { get; set; } = X509VerificationFlags.NoFlag;

        internal void EnsureTrustSource(CertificateTrustSourceKind kind)
        {
            if (SourceKind != CertificateTrustSourceKind.None && SourceKind != kind)
            {
                throw new InvalidOperationException(ClassStrings.ErrorTrustSourceAlreadyConfigured);
            }

            SourceKind = kind;
        }

        internal void AddCustomRoot(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            CustomTrustRoots.Add(certificate);
            EnsureTrustSource(CertificateTrustSourceKind.CustomRoot);
        }

        internal void Validate()
        {
            if (SourceKind == CertificateTrustSourceKind.None)
            {
                throw new InvalidOperationException(ClassStrings.ErrorNoTrustSourceConfigured);
            }

            if (IdentityPinningEnabled && AllowedThumbprints.Count == 0 && AllowedSubjectIssuerPatterns.Count == 0)
            {
                throw new InvalidOperationException(ClassStrings.ErrorNoIdentityConstraintsConfigured);
            }
        }

        internal bool IsIdentityAllowed(string thumbprint, string subject, string issuer)
        {
            // Identity pinning is disabled by default.
            if (!IdentityPinningEnabled)
            {
                return true;
            }

            if (AllowedThumbprints.Count > 0)
            {
                var normalized = NormalizeThumbprint(thumbprint);
                foreach (var allowed in AllowedThumbprints)
                {
                    if (string.Equals(NormalizeThumbprint(allowed), normalized, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            foreach (var pattern in AllowedSubjectIssuerPatterns)
            {
                if (MatchesPattern(pattern, subject, issuer))
                {
                    return true;
                }
            }

            return false;
        }

        internal static string NormalizeThumbprint(string thumbprint)
        {
            if (thumbprint == null)
            {
                return string.Empty;
            }

            // netstandard2.0 does not support string.Replace(string, string, StringComparison).
            return thumbprint.Replace(ClassStrings.Space, string.Empty).ToUpperInvariant();
        }

        private static bool MatchesPattern(CertificateIdentityPattern pattern, string subject, string issuer)
        {
            if (pattern == null)
            {
                return false;
            }

            if (!MatchesCore(pattern.Subject, subject, pattern.MatchKind))
            {
                return false;
            }

            if (pattern.Issuer == null)
            {
                return true;
            }

            return MatchesCore(pattern.Issuer, issuer, pattern.MatchKind);
        }

        private static bool MatchesCore(string expected, string actual, CertificateIdentityMatchKind matchKind)
        {
            var comparison = StringComparison.OrdinalIgnoreCase;

            return matchKind switch
            {
                CertificateIdentityMatchKind.Exact => string.Equals(expected, actual, comparison),
                CertificateIdentityMatchKind.Contains => actual?.IndexOf(expected, comparison) >= 0,
                _ => false
            };
        }
    }
}
