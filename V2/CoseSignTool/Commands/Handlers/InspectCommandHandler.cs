// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Invocation;
using CoseSignTool.Inspection;
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
            FileInfo? file = null;
            foreach (var arg in commandResult.Command.Arguments)
            {
                if (arg.Name == "file")
                {
                    file = parseResult.GetValueForArgument(arg) as FileInfo;
                    break;
                }
            }

            if (file == null || !file.Exists)
            {
                Formatter.WriteError($"File not found: {file?.FullName ?? "null"}");
                Formatter.Flush();
                return (int)ExitCode.FileNotFound;
            }

            // Use the inspection service to inspect the file
            var result = await InspectionService.InspectAsync(file.FullName, extractPayloadPath);
            Formatter.Flush();
            return result;
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