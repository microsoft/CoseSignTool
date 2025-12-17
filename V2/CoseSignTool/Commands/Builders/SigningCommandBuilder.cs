// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Direct;
using CoseSign1.Indirect;
using CoseSignTool.Abstractions;
using CoseSignTool.Output;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Commands.Builders;

/// <summary>
/// Builds signing commands from plugin providers.
/// Centralizes all I/O handling (stdin/stdout/files), factory usage, and output formatting.
/// Plugins only provide configured signing services.
/// </summary>
public class SigningCommandBuilder
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Argument and Option names
        public static readonly string ArgumentNamePayload = "payload";
        public static readonly string OptionNameOutput = "--output";
        public static readonly string OptionAliasOutput = "-o";
        public static readonly string OptionNameSignatureType = "--signature-type";
        public static readonly string OptionAliasSignatureTypeT = "-t";
        public static readonly string OptionAliasSignatureTypeD = "-d";
        public static readonly string OptionNameContentType = "--content-type";
        public static readonly string OptionAliasContentType = "-c";
        public static readonly string OptionNameQuiet = "--quiet";
        public static readonly string OptionAliasQuiet = "-q";
        public static readonly string OptionNameOutputFormat = "output-format";

        // Signature type values
        public static readonly string SignatureTypeIndirect = "indirect";
        public static readonly string SignatureTypeDetached = "detached";
        public static readonly string SignatureTypeEmbedded = "embedded";

        // Default values
        public static readonly string DefaultContentType = "application/octet-stream";

        // Section and key names
        public static readonly string SectionSigningOperation = "Signing Operation";
        public static readonly string KeyCommand = "Command";
        public static readonly string KeyPayload = "Payload";
        public static readonly string KeyOutput = "Output";
        public static readonly string KeySignatureType = "Signature Type";
        public static readonly string KeyEmbedPayload = "Embed Payload";
        public static readonly string KeyContentType = "Content Type";
        public static readonly string KeySignatureSize = "Signature Size";

        // Display values
        public static readonly string EmbedYes = "Yes (embedded)";
        public static readonly string EmbedNo = "No (detached)";

        // Success and error messages
        public static readonly string SuccessSigned = "Successfully signed payload";
        public static readonly string ErrorCancelled = "Operation cancelled by user";
        public static readonly string ErrorTimeout = "Operation timed out waiting for input/output";
        public static readonly string ErrorPayloadNotFound = "Payload file not found: {0}";
        public static readonly string ErrorSigningFailed = "Signing failed: {0}";
        public static readonly string ErrorUnknownSignatureType = "Unknown signature type: {0}";
        public static readonly string ErrorFileNotFound = "File not found: {0}";

        // Standard options set
        public static readonly string StandardOptionOutput = "output";
        public static readonly string StandardOptionDetached = "detached";
        public static readonly string StandardOptionSignatureType = "signature-type";
        public static readonly string StandardOptionContentType = "content-type";
        public static readonly string StandardOptionQuiet = "quiet";
        public static readonly string StandardOptionHelp = "help";

        // Plugin options key
        public static readonly string PluginOptionLoggerFactory = "__loggerFactory";

        // Format strings
        public static readonly string FormatSignatureSize = "{0:N0} bytes";
        public static readonly string FormatOutputFileCose = "{0}.cose";

        // Description templates
        public static readonly string DescriptionPayload = """
            Path to payload file to sign. Use '-' or omit to read from stdin.
              Examples:
                myfile.txt          - Sign file from disk
                -                   - Read from stdin
                (omitted)           - Read from stdin (default)
            """;

        public static readonly string DescriptionOutput = """
            Output path for the signature file. Use '-' for stdout.
              Default behavior:
                - If payload is a file: <payload>.cose
                - If payload is stdin: stdout
              Examples:
                --output signature.cose  - Write to file
                --output -               - Write to stdout
                (omitted)                - Use default
            """;

        public static readonly string DescriptionSignatureType = """
            Signature generation strategy (default: indirect):
              detached - Sign the payload directly, do not embed payload in signature
              embedded - Sign the payload directly, embed payload in signature
              indirect - Sign a hash envelope of the payload (SCITT-compliant, most efficient)
            """;

        public static readonly string DescriptionContentType = """
            MIME type of the payload (default: application/octet-stream).
              Common examples:
                application/octet-stream - Binary data (default)
                text/plain               - Plain text
                application/json         - JSON data
                application/xml          - XML data
            """;

        public static readonly string DescriptionQuiet = """
            Suppress informational messages (errors still shown).
              Automatically enabled when writing to stdout.
              Useful for scripting and pipeline operations.
            """;

        // Command description template
        public static readonly string CommandDescriptionTemplate = """
            {0}

            PIPELINE EXAMPLES:
              # Sign data from stdin, output to stdout:
                echo 'Hello World' | CoseSignTool {1} {2} > signed.cose

              # Sign file, write signature to stdout:
                CoseSignTool {1} myfile.txt {2} --output - > signature.cose

              # Chain with other commands:
                cat document.txt | CoseSignTool {1} {2} | base64 > signed.b64

              # Sign and verify in pipeline:
                echo 'test' | CoseSignTool {1} {2} | CoseSignTool verify -

              # Batch signing multiple files:
                for file in *.txt; do CoseSignTool {1} "$file" {2}; done
            """;
    }

    private readonly IReadOnlyList<ITransparencyProvider>? TransparencyProviders;
    private readonly ILoggerFactory? LoggerFactory;

    public SigningCommandBuilder(
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILoggerFactory? loggerFactory = null)
    {
        TransparencyProviders = transparencyProviders;
        LoggerFactory = loggerFactory;
    }

    /// <summary>
    /// Creates a signing command from a plugin's command provider.
    /// </summary>
    public Command BuildSigningCommand(ISigningCommandProvider provider)
    {
        // Build command description with pipeline examples
        var providerExample = GetProviderExample(provider);
        var commandDescription = string.Format(
            ClassStrings.CommandDescriptionTemplate,
            provider.CommandDescription,
            provider.CommandName,
            providerExample);

        var command = new Command(provider.CommandName, commandDescription);

        // Payload argument - optional for stdin support
        var payloadArgument = new Argument<string?>(
            name: ClassStrings.ArgumentNamePayload,
            description: ClassStrings.DescriptionPayload,
            getDefaultValue: () => null)
        {
            Arity = ArgumentArity.ZeroOrOne
        };

        // Standard output option - managed by main exe
        var outputOption = new Option<string?>(
            name: ClassStrings.OptionNameOutput,
            description: ClassStrings.DescriptionOutput);
        outputOption.AddAlias(ClassStrings.OptionAliasOutput);

        // Signature type option - indirect is default
        var signatureTypeOption = new Option<string>(
            name: ClassStrings.OptionNameSignatureType,
            getDefaultValue: () => ClassStrings.SignatureTypeIndirect,
            description: ClassStrings.DescriptionSignatureType);
        signatureTypeOption.FromAmong(ClassStrings.SignatureTypeDetached, ClassStrings.SignatureTypeEmbedded, ClassStrings.SignatureTypeIndirect);
        signatureTypeOption.AddAlias(ClassStrings.OptionAliasSignatureTypeT);
        signatureTypeOption.AddAlias(ClassStrings.OptionAliasSignatureTypeD);

        // Standard content-type option
        var contentTypeOption = new Option<string>(
            name: ClassStrings.OptionNameContentType,
            getDefaultValue: () => ClassStrings.DefaultContentType,
            description: ClassStrings.DescriptionContentType);
        contentTypeOption.AddAlias(ClassStrings.OptionAliasContentType);

        // Quiet mode for pipeline-friendly output
        var quietOption = new Option<bool>(
            name: ClassStrings.OptionNameQuiet,
            description: ClassStrings.DescriptionQuiet);
        quietOption.AddAlias(ClassStrings.OptionAliasQuiet);

        command.AddArgument(payloadArgument);
        command.AddOption(outputOption);
        command.AddOption(signatureTypeOption);
        command.AddOption(contentTypeOption);
        command.AddOption(quietOption);

        // Let plugin add its specific options (--pfx, --thumbprint, etc.)
        provider.AddCommandOptions(command);

        // Set handler that manages all I/O and uses factories
        command.SetHandler(async (InvocationContext context) =>
        {
            var exitCode = await HandleSigningCommandAsync(
                context,
                provider,
                payloadArgument,
                outputOption,
                signatureTypeOption,
                contentTypeOption,
                quietOption);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private async Task<int> HandleSigningCommandAsync(
        InvocationContext context,
        ISigningCommandProvider provider,
        Argument<string?> payloadArgument,
        Option<string?> outputOption,
        Option<string> signatureTypeOption,
        Option<string> contentTypeOption,
        Option<bool> quietOption)
    {
        var parseResult = context.ParseResult;

        // Get global output format option
        var outputFormat = OutputFormat.Text; // default
        foreach (var option in parseResult.RootCommandResult.Command.Options)
        {
            if (option.Name == ClassStrings.OptionNameOutputFormat)
            {
                var formatValue = parseResult.GetValueForOption(option);
                if (formatValue != null && Enum.TryParse<OutputFormat>(formatValue.ToString(), true, out var parsed))
                {
                    outputFormat = parsed;
                }
                break;
            }
        }

        // Create formatter based on output format (declare outside try for use in catch blocks)
        var formatter = OutputFormatterFactory.Create(outputFormat);

        try
        {

            // Get standard options
            string? payloadPath = parseResult.GetValueForArgument(payloadArgument);
            string? outputPath = parseResult.GetValueForOption(outputOption);
            string signatureType = parseResult.GetValueForOption(signatureTypeOption) ?? ClassStrings.SignatureTypeIndirect;
            string contentType = parseResult.GetValueForOption(contentTypeOption) ?? ClassStrings.DefaultContentType;
            bool quiet = parseResult.GetValueForOption(quietOption);

            // Determine I/O mode
            bool useStdin = string.IsNullOrEmpty(payloadPath) || payloadPath == AssemblyStrings.IO.StdinIndicator;
            bool useStdout = outputPath == AssemblyStrings.IO.StdinIndicator || (useStdin && string.IsNullOrEmpty(outputPath));
            bool suppressOutput = quiet || useStdout;

            // Extract plugin-specific options
            var pluginOptions = ExtractPluginOptions(parseResult, context.ParseResult.CommandResult.Command);

            // Determine if payload will be embedded based on signature type
            // For "detached" type, payload is never embedded
            // For "embedded" type, payload is always embedded
            // For "indirect" type, hash envelope is embedded, but original payload is not
            var normalizedSignatureType = signatureType.ToLowerInvariant();
            bool willEmbedPayload;
            if (normalizedSignatureType == ClassStrings.SignatureTypeDetached)
            {
                willEmbedPayload = false;
            }
            else if (normalizedSignatureType == ClassStrings.SignatureTypeEmbedded)
            {
                willEmbedPayload = true;
            }
            else if (normalizedSignatureType == ClassStrings.SignatureTypeIndirect)
            {
                willEmbedPayload = true; // Hash envelope is embedded
            }
            else
            {
                willEmbedPayload = true;
            }

            if (!suppressOutput)
            {
                formatter.BeginSection(ClassStrings.SectionSigningOperation);
                formatter.WriteKeyValue(ClassStrings.KeyCommand, provider.CommandName);
                formatter.WriteKeyValue(ClassStrings.KeyPayload, useStdin ? AssemblyStrings.IO.StdinDisplayName : payloadPath!);
                formatter.WriteKeyValue(ClassStrings.KeyOutput, useStdout ? AssemblyStrings.IO.StdoutDisplayName : (outputPath ?? $"{payloadPath}{AssemblyStrings.IO.CoseFileExtension}"));
                formatter.WriteKeyValue(ClassStrings.KeySignatureType, signatureType);
                formatter.WriteKeyValue(ClassStrings.KeyEmbedPayload, willEmbedPayload ? ClassStrings.EmbedYes : ClassStrings.EmbedNo);
                formatter.WriteKeyValue(ClassStrings.KeyContentType, contentType);
            }

            // Create a combined cancellation token with timeout for stdin operations
            // This prevents hanging indefinitely when waiting for stdin input
            using var stdinTimeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(30));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                context.GetCancellationToken(),
                stdinTimeoutCts.Token);
            var cancellationToken = linkedCts.Token;

            // Get payload stream - either stdin or file
            // For large files, we stream directly without buffering into memory
            Stream payloadStream;
            bool shouldDisposeStream = true;

            if (useStdin)
            {
                // Use stdin with timeout protection - prevents hanging when no input is piped
                payloadStream = new IO.TimeoutReadStream(Console.OpenStandardInput());
                shouldDisposeStream = true; // TimeoutReadStream should be disposed
            }
            else
            {
                if (!File.Exists(payloadPath))
                {
                    if (!suppressOutput)
                    {
                        formatter.WriteError(string.Format(ClassStrings.ErrorPayloadNotFound, payloadPath));
                        formatter.EndSection();
                    }
                    return 3; // FileNotFound
                }
                // Open file with FileOptions.SequentialScan for better performance on large files
                payloadStream = new FileStream(
                    payloadPath!,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 81920, // 80KB buffer for large file streaming
                    FileOptions.SequentialScan | FileOptions.Asynchronous);
            }

            byte[] signatureBytes;
            try
            {
                // Get configured signing service from plugin
                var signingService = await provider.CreateSigningServiceAsync(pluginOptions);

                // Create signature based on signature type
                // Use the combined cancellation token that includes timeout
                if (normalizedSignatureType == ClassStrings.SignatureTypeIndirect)
                {
                    signatureBytes = await CreateIndirectSignatureAsync(
                        signingService, payloadStream, contentType, cancellationToken);
                }
                else if (normalizedSignatureType == ClassStrings.SignatureTypeEmbedded)
                {
                    signatureBytes = await CreateDirectSignatureAsync(
                        signingService, payloadStream, contentType, embedPayload: true, cancellationToken);
                }
                else if (normalizedSignatureType == ClassStrings.SignatureTypeDetached)
                {
                    signatureBytes = await CreateDirectSignatureAsync(
                        signingService, payloadStream, contentType, embedPayload: false, cancellationToken);
                }
                else
                {
                    throw new InvalidOperationException(string.Format(ClassStrings.ErrorUnknownSignatureType, signatureType));
                }
            }
            finally
            {
                if (shouldDisposeStream)
                {
                    await payloadStream.DisposeAsync();
                }
            }

            // Write signature output
            // With PQC keys and certificate chains, signatures can be 50-100KB+
            if (useStdout)
            {
                // Write to stdout with timeout protection and chunked streaming
                // for large PQC signatures with full certificate chains
                using var stdoutTimeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                using var stdoutLinkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    context.GetCancellationToken(),
                    stdoutTimeoutCts.Token);

                await using var stdout = Console.OpenStandardOutput();
                await WriteToStreamChunkedAsync(stdout, signatureBytes, stdoutLinkedCts.Token);
            }
            else
            {
                var finalOutputPath = outputPath ?? $"{payloadPath}{AssemblyStrings.IO.CoseFileExtension}";
                // Use FileStream with larger buffer for PQC-sized signatures
                await using var fileStream = new FileStream(
                    finalOutputPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 81920, // 80KB buffer for large signatures
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await WriteToStreamChunkedAsync(fileStream, signatureBytes, cancellationToken);
            }

            if (!suppressOutput)
            {
                formatter.WriteSuccess(ClassStrings.SuccessSigned);
                formatter.WriteKeyValue(ClassStrings.KeySignatureSize, string.Format(ClassStrings.FormatSignatureSize, signatureBytes.Length));

                // Display plugin-provided metadata
                var metadata = provider.GetSigningMetadata();
                foreach (var kvp in metadata)
                {
                    formatter.WriteKeyValue(kvp.Key, kvp.Value);
                }

                formatter.EndSection();
            }

            formatter.Flush();
            return 0; // Success
        }
        catch (OperationCanceledException) when (context.GetCancellationToken().IsCancellationRequested)
        {
            // User-initiated cancellation (Ctrl+C)
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError(ClassStrings.ErrorCancelled);
            }
            formatter.Flush();
            return 2; // Cancelled
        }
        catch (OperationCanceledException)
        {
            // Timeout occurred (stdin/stdout timeout)
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError(ClassStrings.ErrorTimeout);
            }
            formatter.Flush();
            return 11; // Timeout
        }
        catch (FileNotFoundException ex)
        {
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError(string.Format(ClassStrings.ErrorFileNotFound, ex.Message));
            }
            formatter.Flush();
            return 3;
        }
        catch (Exception ex)
        {
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError(string.Format(ClassStrings.ErrorSigningFailed, ex.Message));
            }
            formatter.Flush();
            return 10; // SigningFailed
        }
    }

    private Dictionary<string, object?> ExtractPluginOptions(System.CommandLine.Parsing.ParseResult parseResult, Command command)
    {
        var options = new Dictionary<string, object?>();

        // Skip standard options that are handled by the main exe
        var standardOptions = new HashSet<string>
        {
            ClassStrings.StandardOptionOutput,
            ClassStrings.StandardOptionDetached,
            ClassStrings.StandardOptionSignatureType,
            ClassStrings.StandardOptionContentType,
            ClassStrings.StandardOptionQuiet,
            ClassStrings.StandardOptionHelp
        };

        foreach (var option in command.Options)
        {
            if (!standardOptions.Contains(option.Name))
            {
                var value = parseResult.GetValueForOption(option);
                options[option.Name] = value;
            }
        }

        // Add the logger factory so plugins can use it for their internal operations
        if (LoggerFactory != null)
        {
            options[ClassStrings.PluginOptionLoggerFactory] = LoggerFactory;
        }

        return options;
    }

    private async Task<byte[]> CreateDirectSignatureAsync(
        ISigningService<CoseSign1.Abstractions.SigningOptions> signingService,
        Stream payloadStream,
        string contentType,
        bool embedPayload,
        CancellationToken cancellationToken)
    {
        var logger = LoggerFactory?.CreateLogger<DirectSignatureFactory>();
        using var factory = new DirectSignatureFactory(signingService, TransparencyProviders, logger);
        var options = new DirectSignatureOptions { EmbedPayload = embedPayload };
        return await factory.CreateCoseSign1MessageBytesAsync(
            payloadStream, contentType, options, cancellationToken);
    }

    private async Task<byte[]> CreateIndirectSignatureAsync(
        ISigningService<CoseSign1.Abstractions.SigningOptions> signingService,
        Stream payloadStream,
        string contentType,
        CancellationToken cancellationToken)
    {
        var logger = LoggerFactory?.CreateLogger<IndirectSignatureFactory>();
        using var factory = new IndirectSignatureFactory(signingService, TransparencyProviders, logger, LoggerFactory);
        var options = new IndirectSignatureOptions(); // Indirect signatures are always detached (payload not embedded, only hash is signed)
        return await factory.CreateCoseSign1MessageBytesAsync(
            payloadStream, contentType, options, cancellationToken);
    }

    /// <summary>
    /// Gets a short example string for the provider's required options.
    /// </summary>
    private static string GetProviderExample(ISigningCommandProvider provider)
    {
        // Use the provider's own example usage - fully extensible via plugins
        return provider.ExampleUsage;
    }

    /// <summary>
    /// Writes data to a stream in chunks for efficient handling of large PQC signatures.
    /// Uses 64KB chunks to stay below LOH threshold and allow incremental flushing.
    /// </summary>
    /// <param name="stream">The output stream to write to.</param>
    /// <param name="data">The data to write.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private static async Task WriteToStreamChunkedAsync(Stream stream, byte[] data, CancellationToken cancellationToken)
    {
        const int chunkSize = 65536; // 64KB chunks - below LOH threshold, good for streaming

        int offset = 0;
        while (offset < data.Length)
        {
            int remaining = data.Length - offset;
            int writeSize = Math.Min(remaining, chunkSize);

            await stream.WriteAsync(data.AsMemory(offset, writeSize), cancellationToken).ConfigureAwait(false);
            offset += writeSize;

            // Flush periodically for stdout to ensure data flows through pipes
            // This is important for pipeline scenarios where downstream commands are waiting
            if (offset < data.Length || stream == Console.OpenStandardOutput())
            {
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        // Final flush to ensure all data is written
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}