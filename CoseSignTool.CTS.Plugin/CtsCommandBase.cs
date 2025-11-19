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
        { "token-env", "The name of the environment variable containing the access token (default: AZURE_CTS_TOKEN)" },
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
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected static PluginExitCode ValidateCommonParameters(IConfiguration configuration, out int timeoutSeconds, IPluginLogger? logger = null)
    {
        string timeoutString = GetOptionalValue(configuration, "timeout", "30") ?? "30";
        
        if (!int.TryParse(timeoutString, out timeoutSeconds) || timeoutSeconds <= 0)
        {
            logger?.LogError("Invalid timeout value. Must be a positive integer.");
            return PluginExitCode.InvalidArgumentValue;
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Validates that required file paths exist.
    /// </summary>
    /// <param name="filePaths">Dictionary of file descriptions to file paths.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected static PluginExitCode ValidateFilePaths(Dictionary<string, string> filePaths, IPluginLogger? logger = null)
    {
        foreach (KeyValuePair<string, string> kvp in filePaths)
        {
            if (!File.Exists(kvp.Value))
            {
                logger?.LogError($"{kvp.Key} file not found: {kvp.Value}");
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
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>A tuple containing the decoded message, signature bytes, and operation result.</returns>
    protected static async Task<(CoseSign1Message? message, byte[] signatureBytes, PluginExitCode result)> 
        ReadAndDecodeCoseMessage(string signaturePath, CancellationToken cancellationToken, IPluginLogger? logger = null)
    {
        try
        {
            byte[] signatureBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            return (message, signatureBytes, PluginExitCode.Success);
        }
        catch (Exception ex)
        {
            logger?.LogError($"Failed to decode COSE Sign1 message from {signaturePath}: {ex.Message}");
            logger?.LogException(ex);
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
        CancellationTokenSource timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        
        // Register disposal of the timeout CTS when the linked CTS is disposed
        linkedCts.Token.Register(() => timeoutCts.Dispose());
        
        return linkedCts;
    }

    /// <summary>
    /// Writes a JSON result to the specified output file.
    /// </summary>
    /// <param name="outputPath">Path to write the JSON result.</param>
    /// <param name="result">The object to serialize as JSON.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="logger">Optional logger for status reporting.</param>
    protected static async Task WriteJsonResult(string outputPath, object result, CancellationToken cancellationToken, IPluginLogger? logger = null)
    {
        string jsonOutput = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(outputPath, jsonOutput, cancellationToken);
        logger?.LogInformation($"Result written to: {outputPath}");
    }

    /// <summary>
    /// Prints operation status information using the logger.
    /// </summary>
    /// <param name="operation">The operation being performed (e.g., "Registering", "Verifying").</param>
    /// <param name="endpoint">The CTS endpoint URL.</param>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="signatureSize">Size of the signature in bytes.</param>
    /// <param name="additionalInfo">Optional additional information to display.</param>
    protected void PrintOperationStatus(string operation, string endpoint, string payloadPath, 
        string signaturePath, int signatureSize, string? additionalInfo = null)
    {
        Logger.LogInformation($"{operation} COSE Sign1 message with Azure CTS...");
        Logger.LogVerbose($"  Endpoint: {endpoint}");
        Logger.LogVerbose($"  Payload: {payloadPath}");
        Logger.LogVerbose($"  Signature: {signaturePath} ({signatureSize} bytes)");
        
        if (!string.IsNullOrEmpty(additionalInfo))
        {
            Logger.LogVerbose($"  {additionalInfo}");
        }
    }

    /// <summary>
    /// Handles common exceptions and returns appropriate exit codes.
    /// </summary>
    /// <param name="ex">The exception to handle.</param>
    /// <param name="configuration">Configuration for getting timeout value in error messages.</param>
    /// <param name="cancellationToken">The original cancellation token to check if operation was cancelled.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>Appropriate PluginExitCode for the exception type.</returns>
    protected static PluginExitCode HandleCommonException(Exception ex, IConfiguration configuration, CancellationToken cancellationToken, IPluginLogger? logger = null)
    {
        return ex switch
        {
            ArgumentNullException argEx => 
                HandleError($"Missing required argument - {argEx.ParamName}", PluginExitCode.MissingRequiredOption, logger),
            
            FileNotFoundException fileEx => 
                HandleError($"File not found - {fileEx.Message}", PluginExitCode.UserSpecifiedFileNotFound, logger),
            
            OperationCanceledException when cancellationToken.IsCancellationRequested => 
                HandleError("Operation was cancelled.", PluginExitCode.UnknownError, logger),
            
            OperationCanceledException => 
                HandleError($"Operation timed out after {GetOptionalValue(configuration, "timeout", "30")} seconds.", PluginExitCode.UnknownError, logger),
            
            _ => 
                HandleError(ex.Message, PluginExitCode.UnknownError, logger)
        };

        static PluginExitCode HandleError(string message, PluginExitCode code, IPluginLogger? logger)
        {
            logger?.LogError(message);
            return code;
        }
    }

    /// <summary>
    /// Creates an Azure CTS client using the shared helper.
    /// </summary>
    /// <param name="endpoint">The CTS endpoint URL.</param>
    /// <param name="tokenEnvVarName">Name of the environment variable containing the access token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Configured CodeTransparencyClient.</returns>
    protected static Task<CodeTransparencyClient> CreateCtsClient(string endpoint, string? tokenEnvVarName, CancellationToken cancellationToken)
    {
        return CodeTransparencyClientHelper.CreateClientAsync(endpoint, tokenEnvVarName, cancellationToken);
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
            Logger.LogVerbose("Starting CTS operation");
            
            // Get required parameters
            string endpoint = GetRequiredValue(configuration, "endpoint");
            Logger.LogVerbose($"Endpoint: {endpoint}");
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");

            // Get optional parameters
            string? tokenEnvVarName = GetOptionalValue(configuration, "token-env");
            string? outputPath = GetOptionalValue(configuration, "output");

            // Validate common parameters
            PluginExitCode validationResult = ValidateCommonParameters(configuration, out int timeoutSeconds, Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Validate file paths
            Dictionary<string, string> requiredFiles = new Dictionary<string, string>
            {
                { "Payload", payloadPath },
                { "Signature", signaturePath }
            };

            // Add any additional file validation from derived classes
            AddAdditionalFileValidation(requiredFiles, configuration);

            validationResult = ValidateFilePaths(requiredFiles, Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Read and decode COSE message
            (CoseSign1Message message, byte[] signatureBytes, PluginExitCode readResult) = await ReadAndDecodeCoseMessage(signaturePath, cancellationToken, Logger);
            if (readResult != PluginExitCode.Success || message == null)
            {
                return readResult;
            }

            // Create CTS client
            CodeTransparencyClient client = await CreateCtsClient(endpoint, tokenEnvVarName, cancellationToken);

            // Execute the specific operation
            using CancellationTokenSource combinedCts = CreateTimeoutCancellationToken(timeoutSeconds, cancellationToken);
            (PluginExitCode exitCode, object? result) operationResult = await ExecuteSpecificOperation(
                client, message, signatureBytes, endpoint, payloadPath, signaturePath, 
                configuration, combinedCts.Token);

            // Write output if requested
            if (!string.IsNullOrEmpty(outputPath) && operationResult.result != null)
            {
                await WriteJsonResult(outputPath, operationResult.result, cancellationToken, Logger);
            }

            return operationResult.exitCode;
        }
        catch (Exception ex)
        {
            return HandleCommonException(ex, configuration, cancellationToken, Logger);
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
               $"  --token-env     Name of environment variable containing access token{Environment.NewLine}" +
               $"                  (default: AZURE_CTS_TOKEN, uses default Azure credential if not specified){Environment.NewLine}" +
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
