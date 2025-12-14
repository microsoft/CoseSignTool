// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Invocation;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;
using CoseSignTool.IO;
using CoseSignTool.Output;

namespace CoseSignTool.Commands.Handlers;

/// <summary>
/// Handles the 'verify' command for validating COSE Sign1 signatures.
/// </summary>
public class VerifyCommandHandler
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    internal static class ClassStrings
    {
        public static readonly string ArgumentName = "signature";
        public static readonly string SectionTitle = "Verification Operation";
        public static readonly string KeySignature = "Signature";
        public static readonly string KeyPayload = "Payload";
        public static readonly string KeyActiveProviders = "Active Providers";
        public static readonly string ErrorSignatureNotFound = "Signature file not found: {0}";
        public static readonly string ErrorFailedToDecode = "Failed to decode COSE Sign1 message: {0}";
        public static readonly string ErrorVerificationFailed = "Signature verification failed";
        public static readonly string ErrorFailureDetail = "  {0}: {1}";
        public static readonly string ErrorVerifying = "Error verifying signature: {0}";
        public static readonly string SuccessVerified = "Signature verified successfully";
        public static readonly string NullValue = "null";
    }

    private readonly IOutputFormatter Formatter;
    private readonly IReadOnlyList<IVerificationProvider> VerificationProviders;

    /// <summary>
    /// The timeout for waiting for stdin data. Default is 2 seconds.
    /// </summary>
    public static TimeSpan StdinTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Initializes a new instance of the <see cref="VerifyCommandHandler"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    /// <param name="verificationProviders">The verification providers to use for validation.</param>
    public VerifyCommandHandler(IOutputFormatter? formatter = null, IReadOnlyList<IVerificationProvider>? verificationProviders = null)
    {
        Formatter = formatter ?? new TextOutputFormatter();
        VerificationProviders = verificationProviders ?? Array.Empty<IVerificationProvider>();
    }

    /// <summary>
    /// Handles the verify command asynchronously.
    /// </summary>
    /// <param name="context">The invocation context containing command arguments and options.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public Task<int> HandleAsync(InvocationContext context)
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

            // Determine if using stdin
            bool useStdin = string.IsNullOrEmpty(signaturePath) || signaturePath == AssemblyStrings.IO.StdinIndicator;

            // Read signature bytes from stdin or file
            byte[] signatureBytes;
            if (useStdin)
            {
                Formatter.BeginSection(ClassStrings.SectionTitle);
                Formatter.WriteKeyValue(ClassStrings.KeySignature, AssemblyStrings.IO.StdinDisplayName);

                // Read from stdin with timeout wrapper to avoid blocking forever
                using var rawStdin = Console.OpenStandardInput();
                using var timeoutStdin = new TimeoutReadStream(rawStdin, StdinTimeout);
                using var ms = new MemoryStream();
                timeoutStdin.CopyTo(ms);
                signatureBytes = ms.ToArray();

                if (signatureBytes.Length == 0)
                {
                    if (timeoutStdin.TimedOut)
                    {
                        Formatter.WriteError(string.Format(AssemblyStrings.Errors.StdinTimeout, StdinTimeout.TotalSeconds));
                    }
                    else
                    {
                        Formatter.WriteError(AssemblyStrings.Errors.NoStdinData);
                    }
                    Formatter.EndSection();
                    return Task.FromResult((int)ExitCode.FileNotFound);
                }
            }
            else
            {
                if (!File.Exists(signaturePath))
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorSignatureNotFound, signaturePath));
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
                Formatter.WriteError(string.Format(ClassStrings.ErrorFailedToDecode, ex.Message));
                Formatter.EndSection();
                return Task.FromResult((int)ExitCode.InvalidSignature);
            }

            // Check if payload is embedded
            bool hasEmbeddedPayload = message.Content.HasValue && message.Content.Value.Length > 0;
            Formatter.WriteKeyValue(ClassStrings.KeyPayload, hasEmbeddedPayload ? AssemblyStrings.Display.Embedded : AssemblyStrings.Display.Detached);

            // Build validator with all activated providers
            var validatorBuilder = Cose.Sign1Message()
                .ValidateCertificateSignature(allowUnprotectedHeaders: true);

            // Add validators from each activated provider
            var activatedProviders = new List<string>();
            foreach (var provider in VerificationProviders)
            {
                if (provider.IsActivated(parseResult))
                {
                    activatedProviders.Add(provider.ProviderName);
                    var validators = provider.CreateValidators(parseResult);
                    foreach (var validator in validators)
                    {
                        validatorBuilder = validatorBuilder.AddValidator(validator);
                    }
                }
            }

            if (activatedProviders.Count > 0)
            {
                Formatter.WriteKeyValue(ClassStrings.KeyActiveProviders, string.Join(", ", activatedProviders));
            }

            var compositeValidator = validatorBuilder.Build();
            var validationResult = compositeValidator.Validate(message);

            if (validationResult.IsValid)
            {
                Formatter.WriteSuccess(ClassStrings.SuccessVerified);

                // Add metadata from providers
                foreach (var provider in VerificationProviders)
                {
                    if (provider.IsActivated(parseResult))
                    {
                        var metadata = provider.GetVerificationMetadata(parseResult, message, validationResult);
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
            else
            {
                Formatter.WriteError(ClassStrings.ErrorVerificationFailed);
                foreach (var failure in validationResult.Failures)
                {
                    Formatter.WriteError(string.Format(ClassStrings.ErrorFailureDetail, failure.ErrorCode, failure.Message));
                }
                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.VerificationFailed);
            }
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
}