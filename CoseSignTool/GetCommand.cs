// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

public class GetCommand : ValidateCommand
{
    //<inheritdoc />
    public static new readonly Dictionary<string, string> Options =
        // Use the same options as the Validate command but remove Payload and add SaveTo.
        new Dictionary<string, string> { ["-SaveTo"] = "SaveTo", ["-sa"] = "SaveTo" }
        .Concat(ValidateCommand.Options)
            .Where(k => !k.Value.Equals(nameof(PayloadFile), StringComparison.OrdinalIgnoreCase))
            .ToDictionary(k => k.Key, k => k.Value, StringComparer.InvariantCultureIgnoreCase);

    /// <summary>
    /// Specifies a file path to write a copy of the original payload to.
    /// By default, the payload content is written to Standard Out.
    /// </summary>
    public string? SaveTo { get; set; }

    /// <summary>
    /// Creates a GetCommand instance and sets its properties with a CommandLineConfigurationProvider.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider that has loaded the command line arguments.</param>
    public GetCommand(CommandLineConfigurationProvider provider) : base(provider)
    {
        ApplyOptions(provider);
    }

    //<inheritdoc />
    protected internal override void ApplyOptions(CommandLineConfigurationProvider provider)
    {
        SaveTo = GetOptionString(provider, nameof(SaveTo));
        base.ApplyOptions(provider);
    }

    // This is consumed by ValidateCommand.Run, which uses it in place of the call to CoseParser.Validate.
    protected internal override ValidationResult RunCoseHandlerCommand(
        Stream signature, FileInfo? payloadFile, List<X509Certificate2>? rootCerts,
        X509RevocationMode revocationMode, string? commonName, bool allowUntrusted)
    {
        // Get the embedded payload content.
        string? content = CoseHandler.GetPayload(signature, out ValidationResult result, rootCerts, revocationMode, commonName);

        // Write the content to the specified file, if any, or else pipe to STDOUT.
        if (content is null)
        {
            Console.Error.WriteLine("The signed payload could not be read.");
        }
        else
        {
            // If the user declared an output file, write to it.
            if (!string.IsNullOrEmpty(SaveTo))
            {
                File.WriteAllText(SaveTo, content);
                Console.WriteLine($"Signed payload written to {SaveTo}");
            }
            // No output file, so write to STDOUT.
            else
            {
                using Stream output = Console.OpenStandardOutput();
                using StreamWriter sr = new(output);
                sr.Write(content);
            }
        }

        return result;
    }

    /// <inheritdoc/>
    public static new string Usage => $"{BaseUsageString}{UsageString}{SharedOptionsText}";

    // The usage text to display. Each line should have no more than 120 characters to avoid wrapping. Break is here:  *V*
    // Shared options are inherited from ValidateCommand.
    protected new const string UsageString = @"
Get command: Retrieves and decodes the original payload from a COSE embed signed file or piped signature, writes it to a
    file or to the console, and writes any validation errors to Standard Error.

Options:

    SignatureFile / sigfile / sf: Required, pipeable. The file or piped stream containing the COSE signature.

    SaveTo /sa: Specifies a file path to write the decoded payload content to.
        If no path is specified, output will be written to console.
";
}
