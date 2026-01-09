// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Commands.Handlers;

using System.CommandLine.Invocation;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Abstractions.IO;
using CoseSignTool.Inspection;
using CoseSignTool.Output;

/// <summary>
/// Handles the 'inspect' command for examining COSE Sign1 signatures.
/// </summary>
public class InspectCommandHandler
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ArgumentName = "file";
        public static readonly string ErrorInspecting = "Error inspecting file: {0}";
    }

    private readonly IOutputFormatter Formatter;
    private readonly CoseInspectionService InspectionService;
    private readonly IConsole Console;

    /// <summary>
    /// The timeout for waiting for stdin data. Default is 2 seconds.
    /// </summary>
    public TimeSpan StdinTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Initializes a new instance of the <see cref="InspectCommandHandler"/> class.
    /// </summary>
    /// <param name="console">Console I/O abstraction. Required for stream access.</param>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="console"/> is null.</exception>
    public InspectCommandHandler(IConsole console, IOutputFormatter? formatter = null)
    {
        Console = console ?? throw new ArgumentNullException(nameof(console));
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
                if (arg.Name == ClassStrings.ArgumentName)
                {
                    filePath = parseResult.GetValueForArgument(arg) as string;
                    break;
                }
            }

            // Determine if using stdin
            bool useStdin = string.IsNullOrEmpty(filePath) || filePath == AssemblyStrings.IO.StdinIndicator;

            if (useStdin)
            {
                // IConsole.StandardInput already has timeout protection via SystemConsole
                using var ms = new MemoryStream();
                await Console.StandardInput.CopyToAsync(ms);
                var signatureBytes = ms.ToArray();

                if (signatureBytes.Length == 0)
                {
                    Formatter.WriteError(AssemblyStrings.Errors.NoStdinData);
                    Formatter.Flush();
                    return (int)ExitCode.FileNotFound;
                }

                // Create temp file for inspection (inspection service works with file paths)
                var tempFile = Path.GetTempFileName();
                try
                {
                    await File.WriteAllBytesAsync(tempFile, signatureBytes);
                    var result = await InspectionService.InspectAsync(tempFile, extractPayloadPath, AssemblyStrings.IO.StdinDisplayName);
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
                    Formatter.WriteError(string.Format(AssemblyStrings.Errors.FileNotFound, filePath));
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
            Formatter.WriteError(string.Format(ClassStrings.ErrorInspecting, ex.Message));
            Formatter.Flush();
            return (int)ExitCode.InspectionFailed;
        }
    }
}