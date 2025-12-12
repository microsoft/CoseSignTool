// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Invocation;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSignTool.Output;

namespace CoseSignTool.Commands.Handlers;

/// <summary>
/// Handles the 'verify' command for validating COSE Sign1 signatures.
/// </summary>
public class VerifyCommandHandler
{
    private readonly IOutputFormatter Formatter;

    /// <summary>
    /// Initializes a new instance of the <see cref="VerifyCommandHandler"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    public VerifyCommandHandler(IOutputFormatter? formatter = null)
    {
        Formatter = formatter ?? new TextOutputFormatter();
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
            FileInfo? signature = null;
            foreach (var arg in commandResult.Command.Arguments)
            {
                if (arg.Name == "signature")
                {
                    signature = parseResult.GetValueForArgument(arg) as FileInfo;
                    break;
                }
            }

            if (signature == null || !signature.Exists)
            {
                Formatter.WriteError($"Signature file not found: {signature?.FullName ?? "null"}");
                return Task.FromResult((int)ExitCode.FileNotFound);
            }

            Formatter.BeginSection("Verification Operation");
            Formatter.WriteKeyValue("Signature", signature.FullName);

            // Read and decode the COSE Sign1 message
            var signatureBytes = File.ReadAllBytes(signature.FullName);
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

            // Build and execute validation
            var validator = Cose.Sign1Message()
                .ValidateCertificateSignature(allowUnprotectedHeaders: true)
                .Build();

            var validationResult = validator.Validate(message);

            if (validationResult.IsValid)
            {
                Formatter.WriteSuccess("Signature verified successfully");
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