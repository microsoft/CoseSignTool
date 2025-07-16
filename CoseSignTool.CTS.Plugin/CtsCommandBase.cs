// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.CTS.Plugin;

using System.Text.Json;
using System.Security.Cryptography.Cose;

/// <summary>
/// Base class for Azure Code Transparency Service commands that provides common functionality
/// for parameter validation, file operations, error handling, and result output.
/// </summary>
public abstract class CtsCommandBase : PluginCommandBase
{
    /// <summary>
    /// Common command options shared across all CTS commands.
    /// </summary>
    protected static readonly Dictionary<string, string> CommonOptions = new()
    {
        { "endpoint", "The Azure Code Transparency Service endpoint URL" },
        { "credential", "The path to a JSON file containing Azure credentials (optional - uses default Azure credential if not specified)" },
        { "payload", "The file path to the payload file" },
        { "signature", "The file path to the COSE Sign1 signature file" },
        { "output", "The file path where the result will be written (optional)" },
        { "timeout", "Timeout in seconds for the operation (default: 30)" }
    };

    /// <summary>
    /// Validates common parameters and returns parsed timeout value.
    /// </summary>
    /// <param name="configuration">The configuration containing command arguments.</param>
    /// <param name="timeoutSeconds">The parsed timeout value in seconds.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected static PluginExitCode ValidateCommonParameters(IConfiguration configuration, out int timeoutSeconds)
    {
        string timeoutString = GetOptionalValue(configuration, "timeout", "30") ?? "30";
        
        if (!int.TryParse(timeoutString, out timeoutSeconds) || timeoutSeconds <= 0)
        {
            Console.Error.WriteLine("Error: Invalid timeout value. Must be a positive integer.");
            return PluginExitCode.InvalidArgumentValue;
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Validates that required file paths exist.
    /// </summary>
    /// <param name="filePaths">Dictionary of file descriptions to file paths.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected static PluginExitCode ValidateFilePaths(Dictionary<string, string> filePaths)
    {
        foreach (var kvp in filePaths)
        {
            if (!File.Exists(kvp.Value))
            {
                Console.Error.WriteLine($"Error: {kvp.Key} file not found: {kvp.Value}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Reads and decodes a COSE Sign1 message from a file.
    /// </summary>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A tuple containing the decoded message, signature bytes, and operation result.</returns>
    protected static async Task<(CoseSign1Message? message, byte[] signatureBytes, PluginExitCode result)> 
        ReadAndDecodeCoseMessage(string signaturePath, CancellationToken cancellationToken)
    {
        try
        {
            byte[] signatureBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            return (message, signatureBytes, PluginExitCode.Success);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: Failed to decode COSE Sign1 message from {signaturePath}: {ex.Message}");
            return (null, Array.Empty<byte>(), PluginExitCode.InvalidArgumentValue);
        }
    }

    /// <summary>
    /// Creates a timeout-aware cancellation token that combines the provided token with a timeout.
    /// </summary>
    /// <param name="timeoutSeconds">Timeout in seconds.</param>
    /// <param name="cancellationToken">Original cancellation token.</param>
    /// <returns>Combined cancellation token with timeout.</returns>
    protected static CancellationTokenSource CreateTimeoutCancellationToken(int timeoutSeconds, CancellationToken cancellationToken)
    {
        var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        return CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
    }

    /// <summary>
    /// Writes a JSON result to the specified output file.
    /// </summary>
    /// <param name="outputPath">Path to write the JSON result.</param>
    /// <param name="result">The object to serialize as JSON.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    protected static async Task WriteJsonResult(string outputPath, object result, CancellationToken cancellationToken)
    {
        string jsonOutput = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(outputPath, jsonOutput, cancellationToken);
        Console.WriteLine($"Result written to: {outputPath}");
    }

    /// <summary>
    /// Prints operation status information to the console.
    /// </summary>
    /// <param name="operation">The operation being performed (e.g., "Registering", "Verifying").</param>
    /// <param name="endpoint">The CTS endpoint URL.</param>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="signatureSize">Size of the signature in bytes.</param>
    /// <param name="additionalInfo">Optional additional information to display.</param>
    protected static void PrintOperationStatus(string operation, string endpoint, string payloadPath, 
        string signaturePath, int signatureSize, string? additionalInfo = null)
    {
        Console.WriteLine($"{operation} COSE Sign1 message with Azure CTS...");
        Console.WriteLine($"  Endpoint: {endpoint}");
        Console.WriteLine($"  Payload: {payloadPath}");
        Console.WriteLine($"  Signature: {signaturePath} ({signatureSize} bytes)");
        
        if (!string.IsNullOrEmpty(additionalInfo))
        {
            Console.WriteLine($"  {additionalInfo}");
        }
    }

    /// <summary>
    /// Handles common exceptions and returns appropriate exit codes.
    /// </summary>
    /// <param name="ex">The exception to handle.</param>
    /// <param name="configuration">Configuration for getting timeout value in error messages.</param>
    /// <param name="cancellationToken">The original cancellation token to check if operation was cancelled.</param>
    /// <returns>Appropriate PluginExitCode for the exception type.</returns>
    protected static PluginExitCode HandleCommonException(Exception ex, IConfiguration configuration, CancellationToken cancellationToken)
    {
        return ex switch
        {
            ArgumentNullException argEx => 
                HandleError($"Missing required argument - {argEx.ParamName}", PluginExitCode.MissingRequiredOption),
            
            FileNotFoundException fileEx => 
                HandleError($"File not found - {fileEx.Message}", PluginExitCode.UserSpecifiedFileNotFound),
            
            OperationCanceledException when cancellationToken.IsCancellationRequested => 
                HandleError("Operation was cancelled.", PluginExitCode.UnknownError),
            
            OperationCanceledException => 
                HandleError($"Operation timed out after {GetOptionalValue(configuration, "timeout", "30")} seconds.", PluginExitCode.UnknownError),
            
            _ => 
                HandleError(ex.Message, PluginExitCode.UnknownError)
        };

        static PluginExitCode HandleError(string message, PluginExitCode code)
        {
            Console.Error.WriteLine($"Error: {message}");
            return code;
        }
    }

    /// <summary>
    /// Creates an Azure CTS client using the shared helper.
    /// </summary>
    /// <param name="endpoint">The CTS endpoint URL.</param>
    /// <param name="credentialPath">Optional path to credential file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Configured CodeTransparencyClient.</returns>
    protected static Task<CodeTransparencyClient> CreateCtsClient(string endpoint, string? credentialPath, CancellationToken cancellationToken)
    {
        return CodeTransparencyClientHelper.CreateClientAsync(endpoint, credentialPath, cancellationToken);
    }

    /// <summary>
    /// Template method that defines the common execution flow for CTS commands.
    /// Derived classes override the specific operation method.
    /// </summary>
    /// <param name="configuration">Command configuration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Plugin exit code indicating success or failure.</returns>
    public override async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        try
        {
            // Get required parameters
            string endpoint = GetRequiredValue(configuration, "endpoint");
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");

            // Get optional parameters
            string? credentialPath = GetOptionalValue(configuration, "credential");
            string? outputPath = GetOptionalValue(configuration, "output");

            // Validate common parameters
            var validationResult = ValidateCommonParameters(configuration, out int timeoutSeconds);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Validate file paths
            var requiredFiles = new Dictionary<string, string>
            {
                { "Payload", payloadPath },
                { "Signature", signaturePath }
            };

            // Add any additional file validation from derived classes
            AddAdditionalFileValidation(requiredFiles, configuration);

            validationResult = ValidateFilePaths(requiredFiles);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Read and decode COSE message
            var (message, signatureBytes, readResult) = await ReadAndDecodeCoseMessage(signaturePath, cancellationToken);
            if (readResult != PluginExitCode.Success || message == null)
            {
                return readResult;
            }

            // Create CTS client
            CodeTransparencyClient client = await CreateCtsClient(endpoint, credentialPath, cancellationToken);

            // Execute the specific operation
            using var combinedCts = CreateTimeoutCancellationToken(timeoutSeconds, cancellationToken);
            var operationResult = await ExecuteSpecificOperation(
                client, message, signatureBytes, endpoint, payloadPath, signaturePath, 
                configuration, combinedCts.Token);

            // Write output if requested
            if (!string.IsNullOrEmpty(outputPath) && operationResult.result != null)
            {
                await WriteJsonResult(outputPath, operationResult.result, cancellationToken);
            }

            return operationResult.exitCode;
        }
        catch (Exception ex)
        {
            return HandleCommonException(ex, configuration, cancellationToken);
        }
    }

    /// <summary>
    /// Allows derived classes to add additional file validation requirements.
    /// </summary>
    /// <param name="requiredFiles">Dictionary to add additional required files to.</param>
    /// <param name="configuration">Command configuration.</param>
    protected virtual void AddAdditionalFileValidation(Dictionary<string, string> requiredFiles, IConfiguration configuration)
    {
        // Default implementation - no additional files required
    }

    /// <summary>
    /// Executes the specific operation for the derived command (register, verify, etc.).
    /// </summary>
    /// <param name="client">The Azure CTS client.</param>
    /// <param name="message">The decoded COSE Sign1 message.</param>
    /// <param name="signatureBytes">The raw signature bytes.</param>
    /// <param name="endpoint">The CTS endpoint URL.</param>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="configuration">Command configuration.</param>
    /// <param name="cancellationToken">Cancellation token with timeout.</param>
    /// <returns>Tuple containing the exit code and optional result object for JSON output.</returns>
    protected abstract Task<(PluginExitCode exitCode, object? result)> ExecuteSpecificOperation(
        CodeTransparencyClient client,
        CoseSign1Message message,
        byte[] signatureBytes,
        string endpoint,
        string payloadPath,
        string signaturePath,
        IConfiguration configuration,
        CancellationToken cancellationToken);

    /// <summary>
    /// Gets the base usage string common to all CTS commands.
    /// </summary>
    protected virtual string GetBaseUsage(string commandName, string verb)
    {
        return $"CoseSignTool {commandName} --endpoint <endpoint-url> --payload <payload-file> --signature <signature-file> [options]{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"Required arguments:{Environment.NewLine}" +
               $"  --endpoint      The Azure Code Transparency Service endpoint URL{Environment.NewLine}" +
               $"  --payload       The file path to the payload to {verb}{Environment.NewLine}" +
               $"  --signature     The file path to the COSE Sign1 signature file{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"Optional arguments:{Environment.NewLine}" +
               $"  --credential    Path to JSON file containing Azure credentials{Environment.NewLine}" +
               $"                  Format: {{\"token\": \"<access-token>\"}} or {{\"scopes\": [\"<scope1>\", \"<scope2>\"]}}{Environment.NewLine}" +
               $"                  (uses default Azure credential if not specified){Environment.NewLine}" +
               $"  --output        File path where {verb} result will be written{Environment.NewLine}";
    }

    /// <summary>
    /// Gets command-specific examples. Must be implemented by derived classes.
    /// </summary>
    protected abstract string GetExamples();

    /// <summary>
    /// Gets additional optional arguments specific to the command.
    /// </summary>
    protected virtual string GetAdditionalOptionalArguments()
    {
        return string.Empty;
    }
}
