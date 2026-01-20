// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Attests that the message's ToBeSigned (Sig_structure) has been validated via an MST receipt.
/// </summary>
public sealed class MstReceiptToBeSignedAttestor : IToBeSignedAttestor
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Provider = "MST";

        public const string NoReceipt = "No MST receipt present";
        public const string VerificationDisabled = "Receipt verification disabled";
        public const string MissingOfflineKeys = "Offline MST signing keys are not configured";
        public const string OfflineNotSupported = "Offline MST verification is not supported by this build";
        public const string VerificationFailed = "Receipt verification failed";
        public const string VerificationExceptionPrefix = "Receipt verification threw";
        public const string DetailsSeparator = ": ";
    }

    private readonly MstTrustOptions Options;
    private readonly ICodeTransparencyVerifier Verifier;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptToBeSignedAttestor"/> class.
    /// </summary>
    /// <param name="options">MST trust options.</param>
    /// <param name="verifier">Verifier used to validate MST receipts.</param>
    public MstReceiptToBeSignedAttestor(MstTrustOptions options, ICodeTransparencyVerifier verifier)
    {
        Guard.ThrowIfNull(options);
        Guard.ThrowIfNull(verifier);
        Options = options;
        Verifier = verifier;
    }

    /// <inheritdoc />
    public async ValueTask<ToBeSignedAttestationResult> AttestAsync(
        CoseSign1Message message,
        CancellationToken ct = default)
    {
        Guard.ThrowIfNull(message);

        if (!message.HasMstReceipt())
        {
            return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, ClassStrings.NoReceipt);
        }

        var receipts = message.GetMstReceiptBytes();
        if (receipts.Count == 0)
        {
            return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, ClassStrings.NoReceipt);
        }

        if (!Options.VerifyReceipts)
        {
            return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, ClassStrings.VerificationDisabled);
        }

        if (Options.OfflineOnly)
        {
            if (!Options.HasOfflineKeys)
            {
                return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, ClassStrings.MissingOfflineKeys);
            }

            var encoded = message.Encode();
            Exception? lastException = null;

            try
            {
                foreach (var receiptBytes in receipts)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        var verificationOptionsOffline = MstCodeTransparencyOptions.CreateVerificationOptions(Options);

                        var hosts = MstReceiptHostExtractor.ExtractHostCandidates(receiptBytes);
                        if (hosts.Count == 0)
                        {
                            hosts = MstReceiptHostExtractor.ExtractHostCandidates(encoded);
                        }

                        MstCodeTransparencyOptions.ConfigureOfflineKeys(verificationOptionsOffline, Options, hosts);

                        var filtered = MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(encoded, receiptBytes);
                        Verifier.VerifyTransparentStatement(filtered, verificationOptionsOffline, clientOptions: null);

                        return ToBeSignedAttestationResult.Attested(ClassStrings.Provider, details: null);
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;
                    }
                }

                var details = lastException == null
                    ? ClassStrings.VerificationFailed
                    : string.Concat(
                        ClassStrings.VerificationExceptionPrefix,
                        ClassStrings.DetailsSeparator,
                        lastException.GetType().Name,
                        ClassStrings.DetailsSeparator,
                        lastException.Message);

                return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, details);
            }
            catch (Exception ex)
            {
                var details = string.Concat(
                    ClassStrings.VerificationExceptionPrefix,
                    ClassStrings.DetailsSeparator,
                    ex.GetType().Name,
                    ClassStrings.DetailsSeparator,
                    ex.Message);

                return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, details);
            }
        }

        // Online-mode: verify receipts one-at-a-time so a single bad/untrusted receipt doesn't prevent attestation.
        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(Options);
        var encodedOnline = message.Encode();
        Exception? lastOnlineException = null;

        foreach (var receiptBytes in receipts)
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                var filtered = MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(encodedOnline, receiptBytes);
                Verifier.VerifyTransparentStatement(filtered, verificationOptions, clientOptions: null);
                return ToBeSignedAttestationResult.Attested(ClassStrings.Provider, details: null);
            }
            catch (Exception ex)
            {
                lastOnlineException = ex;
            }
        }

        var onlineDetails = lastOnlineException == null
            ? ClassStrings.VerificationFailed
            : string.Concat(
                ClassStrings.VerificationExceptionPrefix,
                ClassStrings.DetailsSeparator,
                lastOnlineException.GetType().Name,
                ClassStrings.DetailsSeparator,
                lastOnlineException.Message);

        return ToBeSignedAttestationResult.NotAttested(ClassStrings.Provider, onlineDetails);
    }
}
