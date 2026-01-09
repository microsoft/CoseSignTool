// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Commands.Handlers;

using System.CommandLine.Invocation;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Indirect;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSignTool.Abstractions;
using CoseSignTool.Abstractions.IO;
using CoseSignTool.Output;
using Microsoft.Extensions.Logging;

/// <summary>
/// Handles the 'verify' command for validating COSE Sign1 signatures.
/// </summary>
public class VerifyCommandHandler
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ArgumentName = "signature";
        public static readonly string SectionTitle = "Verification Operation";
        public static readonly string KeySignature = "Signature";
        public static readonly string KeyPayload = "Payload";
        public static readonly string KeyPayloadFile = "Payload File";
        public static readonly string KeySignatureOnly = "Signature Only";
        public static readonly string KeyActiveProviders = "Active Providers";
        public static readonly string ListSeparatorCommaSpace = ", ";
        public static readonly string ErrorSignatureNotFound = "Signature file not found: {0}";
        public static readonly string ErrorPayloadNotFound = "Payload file not found: {0}";
        public static readonly string ErrorFailedToDecode = "Failed to decode COSE Sign1 message.";
        public static readonly string ErrorFailedToDecodeDetails = "Details: {0}";
        public static readonly string ErrorFailedToDecodeHintBase64 = string.Concat(
            "The signature input appears to be Base64 text, not binary COSE bytes. ",
            "Decode it to bytes first (e.g., PowerShell: [IO.File]::WriteAllBytes('signature.cose', [Convert]::FromBase64String((Get-Content -Raw 'signature.b64'))) ).");
        public static readonly string ErrorKeyMaterialResolutionFailed = "Key material resolution failed";
        public static readonly string ErrorVerificationFailed = "Signature verification failed";
        public static readonly string ErrorFailureDetail = "  {0}: {1}";
        public static readonly string ErrorVerifying = "Error verifying signature: {0}";
        public static readonly string ErrorDetachedRequiresPayload = "Detached signature requires --payload option to specify the original payload file";
        public static readonly string ErrorPayloadHashMismatch = "Payload hash does not match the signed hash in the indirect signature";
        public static readonly string ErrorSigningKeyMaterialNotTrusted = "Signing key material is not trusted";
        public static readonly string SuccessVerified = "Signature verified successfully";
        public static readonly string SuccessSignatureVerified = "Signature verified successfully (payload verification skipped)";
        public static readonly string SuccessPayloadVerified = "Payload hash verification successful";
        public static readonly string WarningMultipleTrustPolicies = string.Concat(
            "Multiple trust policies were provided by active verification providers. ",
            "CoseSignTool will require all of them to be satisfied (AND).");
        public static readonly string TrustPolicyReasonSignatureOnlyMode = "Signature-only mode";
        public static readonly string TrustPolicyReasonNoTrustPolicyProvided =
            "No trust policy was provided by any active verification provider";
        public static readonly string NullValue = "null";
        public static readonly string ValueYes = "Yes";
        public static readonly string ValueNo = "No";
        public static readonly string ValueEmbedded = "Embedded";
        public static readonly string ValueDetached = "Detached";
        public static readonly string ValueIndirect = "Indirect";
    }

    private readonly IOutputFormatter Formatter;
    private readonly IReadOnlyList<IVerificationProvider> VerificationProviders;
    private readonly IConsole Console;
    private readonly ILoggerFactory? LoggerFactory;

    /// <summary>
    /// The timeout for waiting for stdin data. Default is 2 seconds.
    /// </summary>
    public TimeSpan StdinTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Initializes a new instance of the <see cref="VerifyCommandHandler"/> class.
    /// </summary>
    /// <param name="console">Console I/O abstraction. Required for stream access.</param>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    /// <param name="verificationProviders">The verification providers to use for validation.</param>
    /// <param name="loggerFactory">Optional logger factory for diagnostic logging.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="console"/> is null.</exception>
    public VerifyCommandHandler(
        IConsole console,
        IOutputFormatter? formatter = null,
        IReadOnlyList<IVerificationProvider>? verificationProviders = null,
        ILoggerFactory? loggerFactory = null)
    {
        Console = console ?? throw new ArgumentNullException(nameof(console));
        Formatter = formatter ?? new TextOutputFormatter();
        VerificationProviders = verificationProviders ?? Array.Empty<IVerificationProvider>();
        LoggerFactory = loggerFactory;
    }

    /// <summary>
    /// Handles the verify command asynchronously.
    /// </summary>
    /// <param name="context">The invocation context containing command arguments and options.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public Task<int> HandleAsync(InvocationContext context)
    {
        return HandleAsync(context, payloadFile: null, signatureOnly: false);
    }

    /// <summary>
    /// Handles the verify command asynchronously with payload and signature-only options.
    /// </summary>
    /// <param name="context">The invocation context containing command arguments and options.</param>
    /// <param name="payloadFile">Optional payload file for detached/indirect signature verification.</param>
    /// <param name="signatureOnly">If true, only verify the signature without payload verification.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public Task<int> HandleAsync(InvocationContext context, FileInfo? payloadFile, bool signatureOnly)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            // Get bound values from the parse result
            var parseResult = context.ParseResult;
            var commandResult = parseResult.CommandResult;

            // Find the signature argument
            string? signaturePath = null;
            foreach (var arg in commandResult.Command.Arguments)
            {
                if (arg.Name == ClassStrings.ArgumentName)
                {
                    signaturePath = parseResult.GetValueForArgument(arg) as string;
                    break;
                }
            }

            // Validate payload file exists if provided
            if (payloadFile != null && !payloadFile.Exists)
            {
                Formatter.WriteError(string.Format(ClassStrings.ErrorPayloadNotFound, payloadFile.FullName));
                return Task.FromResult((int)ExitCode.FileNotFound);
            }

            // Determine if using stdin
            bool useStdin = string.IsNullOrEmpty(signaturePath) || signaturePath == AssemblyStrings.IO.StdinIndicator;

            // Read signature bytes from stdin or file
            byte[] signatureBytes;
            if (useStdin)
            {
                Formatter.BeginSection(ClassStrings.SectionTitle);
                Formatter.WriteKeyValue(ClassStrings.KeySignature, AssemblyStrings.IO.StdinDisplayName);

                // IConsole.StandardInput already has timeout protection via SystemConsole
                using var ms = new MemoryStream();
                Console.StandardInput.CopyTo(ms);
                signatureBytes = ms.ToArray();

                if (signatureBytes.Length == 0)
                {
                    Formatter.WriteError(AssemblyStrings.Errors.NoStdinData);
                    Formatter.EndSection();
                    return Task.FromResult((int)ExitCode.FileNotFound);
                }
            }
            else
            {
                if (!File.Exists(signaturePath))
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorSignatureNotFound, signaturePath));;
                    return Task.FromResult((int)ExitCode.FileNotFound);
                }

                Formatter.BeginSection(ClassStrings.SectionTitle);
                Formatter.WriteKeyValue(ClassStrings.KeySignature, signaturePath);

                signatureBytes = File.ReadAllBytes(signaturePath);
            }

            CoseSign1Message message;
            try
            {
                message = CoseSign1Message.DecodeSign1(signatureBytes);
            }
            catch (Exception ex)
            {
                Formatter.WriteError(ClassStrings.ErrorFailedToDecode);

                var details = ex.InnerException?.Message ?? ex.Message;
                if (!string.IsNullOrWhiteSpace(details))
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorFailedToDecodeDetails, details));
                }

                if (LooksLikeBase64Text(signatureBytes))
                {
                    Formatter.WriteError(ClassStrings.ErrorFailedToDecodeHintBase64);
                }

                Formatter.EndSection();
                return Task.FromResult((int)ExitCode.InvalidSignature);
            }

            // Determine signature type: embedded, detached, or indirect
            // Check for PayloadHashAlg header (label 258) to identify indirect signatures
            bool hasEmbeddedPayload = message.Content.HasValue && message.Content.Value.Length > 0;
            bool isIndirectSignature = IsIndirectSignature(message);
            
            string signatureType;
            if (isIndirectSignature)
            {
                signatureType = ClassStrings.ValueIndirect;
            }
            else if (hasEmbeddedPayload)
            {
                signatureType = ClassStrings.ValueEmbedded;
            }
            else
            {
                signatureType = ClassStrings.ValueDetached;
            }
            
            Formatter.WriteKeyValue(ClassStrings.KeyPayload, signatureType);
            
            if (payloadFile != null)
            {
                Formatter.WriteKeyValue(ClassStrings.KeyPayloadFile, payloadFile.FullName);
            }
            
            if (signatureOnly)
            {
                Formatter.WriteKeyValue(ClassStrings.KeySignatureOnly, ClassStrings.ValueYes);
            }

            // For detached signatures (non-indirect), payload is REQUIRED to verify the signature
            if (!hasEmbeddedPayload && !isIndirectSignature && payloadFile == null)
            {
                Formatter.WriteError(ClassStrings.ErrorDetachedRequiresPayload);
                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.InvalidArguments);
            }

            // Read payload bytes if provided
            byte[]? payloadBytes = null;
            if (payloadFile != null)
            {
                payloadBytes = File.ReadAllBytes(payloadFile.FullName);
            }

            // Build verification context with options for providers that need them
            var contextOptions = new Dictionary<string, object?>
            {
                [VerificationContext.KeyLoggerFactory] = LoggerFactory,
                [VerificationContext.KeyConsole] = Console
            };
            var verificationContext = new VerificationContext(detachedPayload: payloadBytes, options: contextOptions);

            var providerValidators = new List<IValidator>();
            var activatedProviders = new List<string>();

            var providerTrustPolicies = new List<TrustPolicy>();

            foreach (var provider in VerificationProviders)
            {
                if (!provider.IsActivated(parseResult))
                {
                    continue;
                }

                activatedProviders.Add(provider.ProviderName);

                // Priority order: IVerificationProviderWithContext > IVerificationProvider
                IEnumerable<IValidator> validators;
                if (provider is IVerificationProviderWithContext withContext)
                {
                    validators = withContext.CreateValidators(parseResult, verificationContext);
                }
                else
                {
                    validators = provider.CreateValidators(parseResult);
                }

                providerValidators.AddRange(validators);

                if (provider is IVerificationProviderWithTrustPolicy withTrustPolicy)
                {
                    var policy = withTrustPolicy.CreateTrustPolicy(parseResult, verificationContext);
                    if (policy != null)
                    {
                        providerTrustPolicies.Add(policy);
                    }
                }
            }

            // Build a validator using the fluent Cose.Sign1Message() builder pattern.
            // This demonstrates the V2 API that programmatic callers should use.
            // Providers are responsible for supplying all necessary validators including
            // signature validators (e.g., CertificateSignatureValidator for X.509).
            var builder = Cose.Sign1Message(LoggerFactory);

            // Add validators from activated providers, tracking if any provide signature validation
            bool hasSignatureValidator = false;
            foreach (var validator in providerValidators)
            {
                builder.AddValidator(validator);
                if (validator.Stages.Contains(ValidationStage.Signature))
                {
                    hasSignatureValidator = true;
                }
            }

            // Fallback: if no provider supplied a signature-stage validator, add a no-op
            // validator that logs a warning. This ensures the builder can build successfully
            // while making it clear that no actual signature verification occurred.
            // Real signature validators should be provided by verification providers that
            // understand the signature type (e.g., X509VerificationProvider for X.509).
            if (!hasSignatureValidator)
            {
                var noOpLogger = LoggerFactory?.CreateLogger<Validation.NoOpSignatureValidator>();
                builder.AddValidator(new Validation.NoOpSignatureValidator(noOpLogger));
            }

            // Configure trust policy
            if (signatureOnly)
            {
                // Signature-only mode is intended to validate cryptographic correctness only.
                // It should not fail due to trust policy requirements.
                builder.AllowAllTrust(ClassStrings.TrustPolicyReasonSignatureOnlyMode);
            }
            else if (providerTrustPolicies.Count == 0)
            {
                builder.DenyAllTrust(ClassStrings.TrustPolicyReasonNoTrustPolicyProvided);
            }
            else
            {
                if (providerTrustPolicies.Count > 1)
                {
                    Formatter.WriteWarning(ClassStrings.WarningMultipleTrustPolicies);
                }

                // Combine all provider trust policies into a single AND policy
                var combinedPolicy = providerTrustPolicies.Count == 1
                    ? providerTrustPolicies[0]
                    : TrustPolicy.And(providerTrustPolicies.ToArray());

                builder.OverrideDefaultTrustPolicy(combinedPolicy);
            }

            if (activatedProviders.Count > 0)
            {
                Formatter.WriteKeyValue(
                    ClassStrings.KeyActiveProviders,
                    string.Join(ClassStrings.ListSeparatorCommaSpace, activatedProviders));
            }

            // Build and execute the validator
            var coseValidator = builder.Build();
            var validationResult = coseValidator.Validate(message);

            if (!validationResult.Resolution.IsValid)
            {
                Formatter.WriteError(ClassStrings.ErrorKeyMaterialResolutionFailed);
                foreach (var failure in validationResult.Resolution.Failures)
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorFailureDetail, failure.ErrorCode, failure.Message));
                }
                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.VerificationFailed);
            }

            if (!validationResult.Trust.IsValid)
            {
                Formatter.WriteError(ClassStrings.ErrorSigningKeyMaterialNotTrusted);
                foreach (var failure in validationResult.Trust.Failures)
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorFailureDetail, failure.ErrorCode, failure.Message));
                }
                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.UntrustedCertificate);
            }

            if (!validationResult.Signature.IsValid)
            {
                Formatter.WriteError(ClassStrings.ErrorVerificationFailed);
                foreach (var failure in validationResult.Signature.Failures)
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorFailureDetail, failure.ErrorCode, failure.Message));
                }
                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.InvalidSignature);
            }

            if (!validationResult.PostSignaturePolicy.IsValid)
            {
                Formatter.WriteError(ClassStrings.ErrorVerificationFailed);
                foreach (var failure in validationResult.PostSignaturePolicy.Failures)
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorFailureDetail, failure.ErrorCode, failure.Message));
                }
                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.VerificationFailed);
            }

            var overall = validationResult.Overall;

            // For indirect signatures, optionally verify payload matches the signed hash
            if (isIndirectSignature && payloadBytes != null && !signatureOnly)
            {
                if (!VerifyIndirectPayloadHash(message, payloadBytes))
                {
                    Formatter.WriteError(ClassStrings.ErrorPayloadHashMismatch);
                    Formatter.EndSection();
                    Formatter.Flush();
                    return Task.FromResult((int)ExitCode.VerificationFailed);
                }
                Formatter.WriteSuccess(ClassStrings.SuccessPayloadVerified);
            }

            // Success
            if (signatureOnly)
            {
                Formatter.WriteSuccess(ClassStrings.SuccessSignatureVerified);
            }
            else
            {
                Formatter.WriteSuccess(ClassStrings.SuccessVerified);
            }

            // Add metadata from providers
            foreach (var provider in VerificationProviders)
            {
                if (provider.IsActivated(parseResult))
                {
                    var metadata = provider.GetVerificationMetadata(parseResult, message, validationResult.Overall);
                    foreach (var kvp in metadata)
                    {
                        Formatter.WriteKeyValue(kvp.Key, kvp.Value?.ToString() ?? ClassStrings.NullValue);
                    }
                }
            }

            Formatter.EndSection();
            Formatter.Flush();
            return Task.FromResult((int)ExitCode.Success);
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Formatter.WriteError(string.Format(ClassStrings.ErrorVerifying, ex.Message));
            Formatter.Flush();
            return Task.FromResult((int)ExitCode.VerificationFailed);
        }
    }

    private static bool LooksLikeBase64Text(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0)
        {
            return false;
        }

        // If the input is mostly printable ASCII and consists only of Base64 chars/whitespace,
        // it's probably a Base64-encoded string saved to disk instead of raw COSE bytes.
        int inspected = 0;
        int base64ish = 0;

        foreach (var b in bytes.Take(4096))
        {
            inspected++;
            char c = (char)b;

            if (c is '\r' or '\n' or '\t' or ' ')
            {
                base64ish++;
                continue;
            }

            bool isBase64Char =
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '+' || c == '/' || c == '=' || c == '-' || c == '_';

            if (isBase64Char)
            {
                base64ish++;
            }
            else if (c < 0x20 || c > 0x7E)
            {
                // Non-printable / binary data: very unlikely to be Base64 text.
                return false;
            }
        }

        if (inspected < 16)
        {
            return false;
        }

        return base64ish >= (inspected * 0.98);
    }

    /// <summary>
    /// Determines if the message is an indirect signature by checking for PayloadHashAlg header (label 258).
    /// Uses V2 CoseHashEnvelopeHeaderContributor.HeaderLabels for header label constants.
    /// </summary>
    private static bool IsIndirectSignature(CoseSign1Message message)
    {
        // Check for PayloadHashAlg (258) in protected headers - this indicates a COSE Hash Envelope / indirect signature
        return message.ProtectedHeaders.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg);
    }

    /// <summary>
    /// Verifies that the provided payload matches the hash stored in an indirect signature.
    /// Reads the hash algorithm from PayloadHashAlg header and compares computed hash against embedded hash.
    /// </summary>
    private static bool VerifyIndirectPayloadHash(CoseSign1Message message, byte[] payload)
    {
        if (!message.Content.HasValue)
        {
            return false;
        }

        // Get the hash algorithm from the PayloadHashAlg header
        if (!message.ProtectedHeaders.TryGetValue(
            CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg,
            out var hashAlgValue))
        {
            return false;
        }

        // Read the COSE algorithm ID
        var reader = new CborReader(hashAlgValue.EncodedValue);
        var algId = reader.ReadInt32();

        // Determine the hash algorithm from COSE algorithm ID
        HashAlgorithm? hasher = algId switch
        {
            -16 => SHA256.Create(),  // SHA-256
            -43 => SHA384.Create(),  // SHA-384
            -44 => SHA512.Create(),  // SHA-512
            _ => null
        };

        if (hasher == null)
        {
            return false;
        }

        using (hasher)
        {
            // Compute hash of the payload
            var computedHash = hasher.ComputeHash(payload);

            // The embedded content is the hash value
            var embeddedHash = message.Content.Value.ToArray();

            // Compare the hashes
            return computedHash.SequenceEqual(embeddedHash);
        }
    }

}