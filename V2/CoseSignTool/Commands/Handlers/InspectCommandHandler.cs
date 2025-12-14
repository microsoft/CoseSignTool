// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Invocation;
using CoseSignTool.Inspection;
using CoseSignTool.IO;
using CoseSignTool.Output;

namespace CoseSignTool.Commands.Handlers;

/// <summary>
/// Handles the 'inspect' command for examining COSE Sign1 signatures.
/// </summary>
public class InspectCommandHandler
{
    private readonly IOutputFormatter Formatter;
    private readonly CoseInspectionService InspectionService;

    /// <summary>
    /// The timeout for waiting for stdin data. Default is 2 seconds.
    /// </summary>
    public static TimeSpan StdinTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Initializes a new instance of the <see cref="InspectCommandHandler"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    public InspectCommandHandler(IOutputFormatter? formatter = null)
    {
        Formatter = formatter ?? new TextOutputFormatter();
        InspectionService = new CoseInspectionService(Formatter);
    }

    /// <summary>
    /// Handles the inspect command asynchronously.
    /// </summary>
    /// <param name="context">The invocation context containing command arguments and options.</param>
    /// <param name="extractPayloadPath">Optional path to extract the embedded payload to. Use "-" for stdout.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public async Task<int> HandleAsync(InvocationContext context, string? extractPayloadPath = null)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            // Get bound values from the parse result
            var parseResult = context.ParseResult;
            var commandResult = parseResult.CommandResult;

            // Find the file argument
            string? filePath = null;
            foreach (var arg in commandResult.Command.Arguments)
            {
                if (arg.Name == "file")
                {
                    filePath = parseResult.GetValueForArgument(arg) as string;
                    break;
                }
            }

            // Determine if using stdin
            bool useStdin = string.IsNullOrEmpty(filePath) || filePath == "-";

            if (useStdin)
            {
                // Read from stdin with timeout wrapper to avoid blocking forever
                using var rawStdin = Console.OpenStandardInput();
                using var timeoutStdin = new TimeoutReadStream(rawStdin, StdinTimeout);
                using var ms = new MemoryStream();
                await timeoutStdin.CopyToAsync(ms);
                var signatureBytes = ms.ToArray();

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
                    Formatter.Flush();
                    return (int)ExitCode.FileNotFound;
                }

                // Create temp file for inspection (inspection service works with file paths)
                var tempFile = Path.GetTempFileName();
                try
                {
                    await File.WriteAllBytesAsync(tempFile, signatureBytes);
                    var result = await InspectionService.InspectAsync(tempFile, extractPayloadPath, "<stdin>");
                    Formatter.Flush();
                    return result;
                }
                finally
                {
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                    }
                }
            }
            else
            {
                if (!File.Exists(filePath))
                {
                    Formatter.WriteError($"File not found: {filePath}");
                    Formatter.Flush();
                    return (int)ExitCode.FileNotFound;
                }

                var result = await InspectionService.InspectAsync(filePath, extractPayloadPath);
                Formatter.Flush();
                return result;
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Formatter.WriteError($"Error inspecting file: {ex.Message}");
            Formatter.Flush();
            return (int)ExitCode.InspectionFailed;
        }
    }
}