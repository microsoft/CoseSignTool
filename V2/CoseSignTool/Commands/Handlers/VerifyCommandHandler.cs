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
    private readonly IOutputFormatter _formatter;

    /// <summary>
    /// Initializes a new instance of the <see cref="VerifyCommandHandler"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    public VerifyCommandHandler(IOutputFormatter? formatter = null)
    {
        _formatter = formatter ?? new TextOutputFormatter();
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
                _formatter.WriteError($"Signature file not found: {signature?.FullName ?? "null"}");
                return Task.FromResult((int)ExitCode.FileNotFound);
            }

            _formatter.BeginSection("Verification Operation");
            _formatter.WriteKeyValue("Signature", signature.FullName);

            // Read and decode the COSE Sign1 message
            var signatureBytes = File.ReadAllBytes(signature.FullName);
            CoseSign1Message message;
            try
            {
                message = CoseSign1Message.DecodeSign1(signatureBytes);
            }
            catch (Exception ex)
            {
                _formatter.WriteError($"Failed to decode COSE Sign1 message: {ex.Message}");
                _formatter.EndSection();
                return Task.FromResult((int)ExitCode.InvalidSignature);
            }

            // Check if payload is embedded
            bool hasEmbeddedPayload = message.Content.HasValue && message.Content.Value.Length > 0;
            _formatter.WriteKeyValue("Payload", hasEmbeddedPayload ? "Embedded" : "Detached");

            // Build and execute validation
            var validator = Cose.Sign1Message()
                .ValidateCertificateSignature(allowUnprotectedHeaders: true)
                .Build();

            var validationResult = validator.Validate(message);

            if (validationResult.IsValid)
            {
                _formatter.WriteSuccess("Signature verified successfully");
                _formatter.EndSection();
                _formatter.Flush();
                return Task.FromResult((int)ExitCode.Success);
            }
            else
            {
                _formatter.WriteError("Signature verification failed");
                foreach (var failure in validationResult.Failures)
                {
                    _formatter.WriteError($"  {failure.ErrorCode}: {failure.Message}");
                }
                _formatter.EndSection();
                _formatter.Flush();
                return Task.FromResult((int)ExitCode.VerificationFailed);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _formatter.WriteError($"Error verifying signature: {ex.Message}");
            _formatter.Flush();
            return Task.FromResult((int)ExitCode.VerificationFailed);
        }
    }
}