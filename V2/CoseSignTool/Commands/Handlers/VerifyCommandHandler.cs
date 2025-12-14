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
                if (arg.Name == "signature")
                {
                    signaturePath = parseResult.GetValueForArgument(arg) as string;
                    break;
                }
            }

            // Determine if using stdin
            bool useStdin = string.IsNullOrEmpty(signaturePath) || signaturePath == "-";

            // Read signature bytes from stdin or file
            byte[] signatureBytes;
            if (useStdin)
            {
                Formatter.BeginSection("Verification Operation");
                Formatter.WriteKeyValue("Signature", "<stdin>");

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
                        Formatter.WriteError($"No signature data received from stdin (timed out after {StdinTimeout.TotalSeconds:F0}s)");
                    }
                    else
                    {
                        Formatter.WriteError("No signature data received from stdin");
                    }
                    Formatter.WriteError("No signature data received from stdin");
                    Formatter.EndSection();
                    return Task.FromResult((int)ExitCode.FileNotFound);
                }
            }
            else
            {
                if (!File.Exists(signaturePath))
                {
                    Formatter.WriteError($"Signature file not found: {signaturePath}");
                    return Task.FromResult((int)ExitCode.FileNotFound);
                }

                Formatter.BeginSection("Verification Operation");
                Formatter.WriteKeyValue("Signature", signaturePath);

                signatureBytes = File.ReadAllBytes(signaturePath);
            }
            CoseSign1Message message;
            try
            {
                message = CoseSign1Message.DecodeSign1(signatureBytes);
            }
            catch (Exception ex)
            {
                Formatter.WriteError($"Failed to decode COSE Sign1 message: {ex.Message}");
                Formatter.EndSection();
                return Task.FromResult((int)ExitCode.InvalidSignature);
            }

            // Check if payload is embedded
            bool hasEmbeddedPayload = message.Content.HasValue && message.Content.Value.Length > 0;
            Formatter.WriteKeyValue("Payload", hasEmbeddedPayload ? "Embedded" : "Detached");

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
                Formatter.WriteKeyValue("Active Providers", string.Join(", ", activatedProviders));
            }

            var compositeValidator = validatorBuilder.Build();
            var validationResult = compositeValidator.Validate(message);

            if (validationResult.IsValid)
            {
                Formatter.WriteSuccess("Signature verified successfully");

                // Add metadata from providers
                foreach (var provider in VerificationProviders)
                {
                    if (provider.IsActivated(parseResult))
                    {
                        var metadata = provider.GetVerificationMetadata(parseResult, message, validationResult);
                        foreach (var kvp in metadata)
                        {
                            Formatter.WriteKeyValue(kvp.Key, kvp.Value?.ToString() ?? "null");
                        }
                    }
                }

                Formatter.EndSection();
                Formatter.Flush();
                return Task.FromResult((int)ExitCode.Success);
            }
            else
            {
                Formatter.WriteError("Signature verification failed");
                foreach (var failure in validationResult.Failures)
                {
                    Formatter.WriteError($"  {failure.ErrorCode}: {failure.Message}");
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
            Formatter.WriteError($"Error verifying signature: {ex.Message}");
            Formatter.Flush();
            return Task.FromResult((int)ExitCode.VerificationFailed);
        }
    }
}