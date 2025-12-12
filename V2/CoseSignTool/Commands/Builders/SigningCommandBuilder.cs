// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Invocation;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Direct;
using CoseSign1.Indirect;
using CoseSignTool.Output;
using CoseSignTool.Plugins;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Commands.Builders;

/// <summary>
/// Builds signing commands from plugin providers.
/// Centralizes all I/O handling (stdin/stdout/files), factory usage, and output formatting.
/// Plugins only provide configured signing services.
/// </summary>
public class SigningCommandBuilder
{
    private readonly IReadOnlyList<ITransparencyProvider>? _transparencyProviders;
    private readonly ILoggerFactory? _loggerFactory;

    public SigningCommandBuilder(
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILoggerFactory? loggerFactory = null)
    {
        _transparencyProviders = transparencyProviders;
        _loggerFactory = loggerFactory;
    }

    /// <summary>
    /// Creates a signing command from a plugin's command provider.
    /// </summary>
    public Command BuildSigningCommand(ISigningCommandProvider provider)
    {
        // Build command description with pipeline examples
        var providerExample = GetProviderExample(provider);
        var commandDescription = $"{provider.CommandDescription}\n\n" +
            $"PIPELINE EXAMPLES:\n" +
            $"  # Sign data from stdin, output to stdout:\n" +
            $"    echo 'Hello World' | CoseSignTool {provider.CommandName} {providerExample} > signed.cose\n\n" +
            $"  # Sign file, write signature to stdout:\n" +
            $"    CoseSignTool {provider.CommandName} myfile.txt {providerExample} --output - > signature.cose\n\n" +
            $"  # Chain with other commands:\n" +
            $"    cat document.txt | CoseSignTool {provider.CommandName} {providerExample} | base64 > signed.b64\n\n" +
            $"  # Sign and verify in pipeline:\n" +
            $"    echo 'test' | CoseSignTool {provider.CommandName} {providerExample} | CoseSignTool verify -\n\n" +
            $"  # Batch signing multiple files:\n" +
            $"    for file in *.txt; do CoseSignTool {provider.CommandName} \"$file\" {providerExample}; done";

        var command = new Command(provider.CommandName, commandDescription);

        // Payload argument - optional for stdin support
        var payloadArgument = new Argument<string?>(
            name: "payload",
            description: "Path to payload file to sign. Use '-' or omit to read from stdin.\n" +
                        "  Examples:\n" +
                        "    myfile.txt          - Sign file from disk\n" +
                        "    -                   - Read from stdin\n" +
                        "    (omitted)           - Read from stdin (default)")
        {
            Arity = ArgumentArity.ZeroOrOne
        };
        payloadArgument.SetDefaultValue(null);

        // Standard output option - managed by main exe
        var outputOption = new Option<string?>(
            name: "--output",
            description: "Output path for the signature file. Use '-' for stdout.\n" +
                        "  Default behavior:\n" +
                        "    - If payload is a file: <payload>.cose\n" +
                        "    - If payload is stdin: stdout\n" +
                        "  Examples:\n" +
                        "    --output signature.cose  - Write to file\n" +
                        "    --output -               - Write to stdout\n" +
                        "    (omitted)                - Use default");
        outputOption.AddAlias("-o");

        // Standard detached option
        var detachedOption = new Option<bool>(
            name: "--detached",
            description: "Create a detached signature (payload not embedded in signature).\n" +
                        "  Only applies to 'embedded' signature type (overrides to detached).\n" +
                        "  Has no effect on 'detached' or 'indirect' types.");
        detachedOption.AddAlias("-d");

        // Signature type option - indirect is default
        var signatureTypeOption = new Option<string>(
            name: "--signature-type",
            getDefaultValue: () => "indirect",
            description: "Signature generation strategy (default: indirect):\n" +
                        "  detached - Sign the payload directly, do not embed payload in signature\n" +
                        "  embedded - Sign the payload directly, embed payload in signature\n" +
                        "  indirect - Sign a hash envelope of the payload (SCITT-compliant, most efficient)");
        signatureTypeOption.FromAmong("detached", "embedded", "indirect");
        signatureTypeOption.AddAlias("-t");

        // Standard content-type option
        var contentTypeOption = new Option<string>(
            name: "--content-type",
            getDefaultValue: () => "application/octet-stream",
            description: "MIME type of the payload (default: application/octet-stream).\n" +
                        "  Common examples:\n" +
                        "    application/octet-stream - Binary data (default)\n" +
                        "    text/plain               - Plain text\n" +
                        "    application/json         - JSON data\n" +
                        "    application/xml          - XML data");
        contentTypeOption.AddAlias("-c");

        // Quiet mode for pipeline-friendly output
        var quietOption = new Option<bool>(
            name: "--quiet",
            description: "Suppress informational messages (errors still shown).\n" +
                        "  Automatically enabled when writing to stdout.\n" +
                        "  Useful for scripting and pipeline operations.");
        quietOption.AddAlias("-q");

        command.AddArgument(payloadArgument);
        command.AddOption(outputOption);
        command.AddOption(detachedOption);
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
                detachedOption,
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
        Option<bool> detachedOption,
        Option<string> signatureTypeOption,
        Option<string> contentTypeOption,
        Option<bool> quietOption)
    {
        var parseResult = context.ParseResult;

        // Get global output format option
        var outputFormat = OutputFormat.Text; // default
        foreach (var option in parseResult.RootCommandResult.Command.Options)
        {
            if (option.Name == "output-format")
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
            bool detached = parseResult.GetValueForOption(detachedOption);
            string signatureType = parseResult.GetValueForOption(signatureTypeOption) ?? "indirect";
            string contentType = parseResult.GetValueForOption(contentTypeOption) ?? "application/octet-stream";
            bool quiet = parseResult.GetValueForOption(quietOption);

            // Determine I/O mode
            bool useStdin = string.IsNullOrEmpty(payloadPath) || payloadPath == "-";
            bool useStdout = outputPath == "-" || (useStdin && string.IsNullOrEmpty(outputPath));
            bool suppressOutput = quiet || useStdout;

            // Extract plugin-specific options
            var pluginOptions = ExtractPluginOptions(parseResult, context.ParseResult.CommandResult.Command);

            if (!suppressOutput)
            {
                formatter.BeginSection("Signing Operation");
                formatter.WriteKeyValue("Command", provider.CommandName);
                formatter.WriteKeyValue("Payload", useStdin ? "<stdin>" : payloadPath!);
                formatter.WriteKeyValue("Output", useStdout ? "<stdout>" : (outputPath ?? $"{payloadPath}.cose"));
                formatter.WriteKeyValue("Signature Type", signatureType);
                formatter.WriteKeyValue("Embed Payload", detached ? "No (detached)" : "Yes (embedded)");
                formatter.WriteKeyValue("Content Type", contentType);
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
                // Use stdin directly as a stream - don't buffer into memory
                // The factories support streaming and will read incrementally
                payloadStream = Console.OpenStandardInput();
                shouldDisposeStream = false; // Don't dispose stdin
            }
            else
            {
                if (!File.Exists(payloadPath))
                {
                    if (!suppressOutput)
                    {
                        formatter.WriteError($"Payload file not found: {payloadPath}");
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
                signatureBytes = signatureType.ToLowerInvariant() switch
                {
                    "indirect" => await CreateIndirectSignatureAsync(
                        signingService, payloadStream, contentType, detached, cancellationToken),
                    "embedded" => await CreateDirectSignatureAsync(
                        signingService, payloadStream, contentType, embedPayload: true, cancellationToken),
                    "detached" => await CreateDirectSignatureAsync(
                        signingService, payloadStream, contentType, !detached, cancellationToken),
                    _ => throw new InvalidOperationException($"Unknown signature type: {signatureType}")
                };
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
                var finalOutputPath = outputPath ?? $"{payloadPath}.cose";
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
                formatter.WriteSuccess("Successfully signed payload");
                formatter.WriteKeyValue("Signature Size", $"{signatureBytes.Length:N0} bytes");

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
                formatter.WriteError("Operation cancelled by user");
            }
            formatter.Flush();
            return 2; // Cancelled
        }
        catch (OperationCanceledException)
        {
            // Timeout occurred (stdin/stdout timeout)
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError("Operation timed out waiting for input/output");
            }
            formatter.Flush();
            return 11; // Timeout
        }
        catch (FileNotFoundException ex)
        {
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError($"File not found: {ex.Message}");
            }
            formatter.Flush();
            return 3;
        }
        catch (Exception ex)
        {
            if (!context.ParseResult.GetValueForOption(quietOption))
            {
                formatter.WriteError($"Signing failed: {ex.Message}");
            }
            formatter.Flush();
            return 10; // SigningFailed
        }
    }

    private Dictionary<string, object?> ExtractPluginOptions(System.CommandLine.Parsing.ParseResult parseResult, Command command)
    {
        var options = new Dictionary<string, object?>();

        // Skip standard options that are handled by the main exe
        var standardOptions = new HashSet<string> { "output", "detached", "signature-type", "content-type", "quiet", "help" };

        foreach (var option in command.Options)
        {
            if (!standardOptions.Contains(option.Name))
            {
                var value = parseResult.GetValueForOption(option);
                options[option.Name] = value;
            }
        }

        // Add the logger factory so plugins can use it for their internal operations
        if (_loggerFactory != null)
        {
            options["__loggerFactory"] = _loggerFactory;
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
        var logger = _loggerFactory?.CreateLogger<DirectSignatureFactory>();
        using var factory = new DirectSignatureFactory(signingService, _transparencyProviders, logger);
        var options = new DirectSignatureOptions { EmbedPayload = embedPayload };
        return await factory.CreateCoseSign1MessageBytesAsync(
            payloadStream, contentType, options, cancellationToken);
    }

    private async Task<byte[]> CreateIndirectSignatureAsync(
        ISigningService<CoseSign1.Abstractions.SigningOptions> signingService,
        Stream payloadStream,
        string contentType,
        bool detached,
        CancellationToken cancellationToken)
    {
        var logger = _loggerFactory?.CreateLogger<IndirectSignatureFactory>();
        using var factory = new IndirectSignatureFactory(signingService, _transparencyProviders, logger, _loggerFactory);
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