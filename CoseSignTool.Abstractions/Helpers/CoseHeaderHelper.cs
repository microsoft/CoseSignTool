// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Helpers;

using System.Security.Cryptography.Cose;
using System.Text.Json;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using CoseSign1.Headers.Local;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Shared helper class for processing COSE headers from command line or file inputs.
/// This class provides functionality to parse and validate headers for both direct and indirect signing commands.
/// </summary>
public static class CoseHeaderHelper
{
    /// <summary>
    /// Header options that can be used in command definitions.
    /// </summary>
    public static readonly Dictionary<string, string> HeaderOptions = new()
    {
        { "int-headers", "Path to a JSON file containing headers with int32 values" },
        { "string-headers", "Path to a JSON file containing headers with string values" },
        { "int-protected-headers", "Comma-separated list of protected headers with int32 values (format: label=value)" },
        { "string-protected-headers", "Comma-separated list of protected headers with string values (format: label=value)" },
        { "int-unprotected-headers", "Comma-separated list of unprotected headers with int32 values (format: label=value)" },
        { "string-unprotected-headers", "Comma-separated list of unprotected headers with string values (format: label=value)" }
    };

    /// <summary>
    /// Creates a CoseHeaderExtender from header collections.
    /// </summary>
    /// <param name="intHeaders">Collection of headers with int32 values.</param>
    /// <param name="stringHeaders">Collection of headers with string values.</param>
    /// <returns>A CoseHeaderExtender if headers are present, null otherwise.</returns>
    public static CoseHeaderExtender? CreateHeaderExtender(
        List<CoseHeader<int>>? intHeaders, 
        List<CoseHeader<string>>? stringHeaders)
    {
        // Only create extender if we have headers
        if ((intHeaders?.Count > 0) || (stringHeaders?.Count > 0))
        {
            // Convert headers to CoseHeaderMaps
            CoseHeaderMap? protectedHeaders = null;
            CoseHeaderMap? unProtectedHeaders = null;
            
            if (intHeaders?.Count > 0)
            {
                protectedHeaders = intHeaders.Where(h => h.IsProtected).ToCoseHeaderMap();
                unProtectedHeaders = intHeaders.Where(h => !h.IsProtected).ToCoseHeaderMap();
            }

            if (stringHeaders?.Count > 0)
            {
                protectedHeaders = stringHeaders.Where(h => h.IsProtected).ToCoseHeaderMap(protectedHeaders);
                unProtectedHeaders = stringHeaders.Where(h => !h.IsProtected).ToCoseHeaderMap(unProtectedHeaders);
            }

            // Create extender with delegate pattern
            return new CoseHeaderExtender(
                (existingProtectedHeaderMap) => protectedHeaders?.MergeHeaderMap(existingProtectedHeaderMap) ?? existingProtectedHeaderMap,
                (existingUnprotectedHeaderMap) => unProtectedHeaders?.MergeHeaderMap(existingUnprotectedHeaderMap) ?? existingUnprotectedHeaderMap
            );
        }

        return null;
    }

    /// <summary>
    /// Parses headers from configuration and creates a CoseHeaderExtender if headers are present.
    /// </summary>
    /// <param name="configuration">The configuration containing header parameters.</param>
    /// <returns>A CoseHeaderExtender if headers are found, null otherwise.</returns>
    public static CoseHeaderExtender? CreateHeaderExtender(IConfiguration configuration)
    {
        List<CoseHeader<int>>? intHeaders = null;
        List<CoseHeader<string>>? stringHeaders = null;

        // Try to load headers from files first
        intHeaders = GetHeadersFromFile<int>(configuration, "int-headers");
        stringHeaders = GetHeadersFromFile<string>(configuration, "string-headers");

        // If no file headers, try command line headers
        if (intHeaders == null)
        {
            intHeaders = new List<CoseHeader<int>>();
            GetHeadersFromCommandLine(configuration, "int-protected-headers", true, intHeaders, ParseIntValue);
            GetHeadersFromCommandLine(configuration, "int-unprotected-headers", false, intHeaders, ParseIntValue);
        }

        if (stringHeaders == null)
        {
            stringHeaders = new List<CoseHeader<string>>();
            GetHeadersFromCommandLine(configuration, "string-protected-headers", true, stringHeaders, ParseStringValue);
            GetHeadersFromCommandLine(configuration, "string-unprotected-headers", false, stringHeaders, ParseStringValue);
        }

        // Use the overload to create the header extender
        return CreateHeaderExtender(intHeaders, stringHeaders);
    }

    /// <summary>
    /// Gets the header usage documentation for command help.
    /// </summary>
    /// <returns>Formatted string describing header options.</returns>
    public static string HeaderUsage => $"{Environment.NewLine}" +
           $"Header options (optional):{Environment.NewLine}" +
           $"  --int-headers              Path to JSON file containing headers with int32 values{Environment.NewLine}" +
           $"  --string-headers           Path to JSON file containing headers with string values{Environment.NewLine}" +
           $"  --int-protected-headers    Comma-separated protected headers with int32 values (format: label=value){Environment.NewLine}" +
           $"  --string-protected-headers Comma-separated protected headers with string values (format: label=value){Environment.NewLine}" +
           $"  --int-unprotected-headers  Comma-separated unprotected headers with int32 values (format: label=value){Environment.NewLine}" +
           $"  --string-unprotected-headers Comma-separated unprotected headers with string values (format: label=value){Environment.NewLine}";

    /// <summary>
    /// Gets examples of header usage for command documentation.
    /// </summary>
    /// <returns>Formatted string with header usage examples.</returns>
    public static string HeaderExamples => $"{Environment.NewLine}" +
           $"  # Using command-line headers{Environment.NewLine}" +
           $"  --int-protected-headers created-at=1234567890,version=1{Environment.NewLine}" +
           $"  --string-unprotected-headers app-name=MyApp,environment=prod{Environment.NewLine}" +
           $"{Environment.NewLine}" +
           $"  # Using header files{Environment.NewLine}" +
           $"  --int-headers headers.json --string-headers strings.json{Environment.NewLine}" +
           $"{Environment.NewLine}" +
           $"  # JSON file format example:{Environment.NewLine}" +
           $"  # [{{{Environment.NewLine}" +
           $"  #   \"label\": \"created-at\",{Environment.NewLine}" +
           $"  #   \"value\": 1234567890,{Environment.NewLine}" +
           $"  #   \"protected\": true{Environment.NewLine}" +
           $"  # }}]{Environment.NewLine}";

    /// <summary>
    /// Loads headers from a JSON file.
    /// </summary>
    /// <typeparam name="T">The type of header values (int or string).</typeparam>
    /// <param name="configuration">The configuration containing file path.</param>
    /// <param name="key">The configuration key for the file path.</param>
    /// <returns>List of headers if file exists and is valid, null otherwise.</returns>
    private static List<CoseHeader<T>>? GetHeadersFromFile<T>(IConfiguration configuration, string key)
    {
        string? filePath = configuration[key];
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            return null;
        }

        try
        {
            string json = File.ReadAllText(filePath);
            return JsonSerializer.Deserialize<List<CoseHeader<T>>>(json);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"Failed to parse header file '{filePath}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Parses headers from command line input.
    /// </summary>
    /// <typeparam name="T">The type of header values.</typeparam>
    /// <param name="configuration">The configuration containing command line values.</param>
    /// <param name="key">The configuration key for the headers.</param>
    /// <param name="isProtected">Whether the headers are protected.</param>
    /// <param name="headers">The list to add parsed headers to.</param>
    /// <param name="valueParser">Function to parse header values.</param>
    private static void GetHeadersFromCommandLine<T>(
        IConfiguration configuration, 
        string key, 
        bool isProtected, 
        List<CoseHeader<T>> headers,
        Func<string, T> valueParser)
    {
        string? headerString = configuration[key];
        if (string.IsNullOrEmpty(headerString))
        {
            return;
        }

        string[] headerPairs = headerString.Split(',');
        foreach (string headerPair in headerPairs)
        {
            string[] parts = headerPair.Split('=', 2);
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid header format '{headerPair}'. Expected 'label=value'.");
            }

            string label = parts[0].Trim();
            string valueString = parts[1].Trim();

            if (string.IsNullOrEmpty(label))
            {
                throw new ArgumentException($"Header label cannot be empty in '{headerPair}'.");
            }

            try
            {
                T value = valueParser(valueString);
                headers.Add(new CoseHeader<T>(label, value, isProtected));
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Failed to parse header value '{valueString}' for label '{label}': {ex.Message}", ex);
            }
        }
    }

    /// <summary>
    /// Parses an integer value from string.
    /// </summary>
    /// <param name="value">The string value to parse.</param>
    /// <returns>Parsed integer value.</returns>
    private static int ParseIntValue(string value)
    {
        if (!int.TryParse(value, out int result))
        {
            throw new FormatException($"'{value}' is not a valid integer.");
        }
        return result;
    }

    /// <summary>
    /// Parses a string value, removing quotes if present.
    /// </summary>
    /// <param name="value">The string value to parse.</param>
    /// <returns>Parsed string value.</returns>
    private static string ParseStringValue(string value)
    {
        // Remove surrounding quotes if present
        if ((value.StartsWith('"') && value.EndsWith('"')) ||
            (value.StartsWith('\'') && value.EndsWith('\'')))
        {
            return value[1..^1];
        }
        return value;
    }
}
