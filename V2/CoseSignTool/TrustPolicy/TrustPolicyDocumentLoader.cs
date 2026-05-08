// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.TrustPolicy;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using CoseSign1.Validation.TrustFrontends.Json;

/// <summary>
/// CLI helper that loads a <c>.coseTrustPolicy.json</c> document, runs it through the
/// <see cref="CoseTpJsonFrontend"/> translator, binds host-supplied parameters, and produces a
/// <see cref="CompiledTrustPlan"/> per design decision D8. Pack defaults are bypassed; pack fact
/// producers stay available via the supplied service provider.
/// </summary>
internal static class TrustPolicyDocumentLoader
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrTrustPolicyFileNotFound = "Trust-policy file not found: {0}";
        public const string ErrTrustPolicyHttpFailedFormat = "Failed to fetch trust-policy from '{0}': {1}";
        public const string ErrTrustPolicyTranslateFailed = "Trust-policy translation failed:";
        public const string ErrTrustPolicyDiagnosticFormat = "  [{0}] {1}";
        public const string ErrTrustPolicyDiagnosticWithLocationFormat = "  [{0}] {1} (at {2})";
        public const string ErrTrustPolicyParamFormat = "Invalid --trust-policy-param '{0}': expected 'name=jsonValue'.";
        public const string ErrTrustPolicyParamJsonFormat = "Invalid --trust-policy-param value for '{0}': {1}";
        public const string SchemeFile = "file://";
        public const string SchemeHttp = "http://";
        public const string SchemeHttps = "https://";
        public const string ParamSeparator = "=";
        public const string DocumentSourcePrefixFile = "file://";
        public const char PathSlashWindows = '\\';
        public const char PathSlashUnix = '/';
        public static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(15);
    }

    /// <summary>
    /// Loads, parses, validates, walks, and binds the document at <paramref name="pathOrUrl"/>.
    /// On translation failure, diagnostics are written to <paramref name="errorWriter"/> and the
    /// method returns <see langword="null"/>.
    /// </summary>
    /// <param name="pathOrUrl">A local path, <c>file://</c> URI, or http(s) URL.</param>
    /// <param name="rawParams">Raw <c>--trust-policy-param name=jsonValue</c> tokens.</param>
    /// <param name="services">DI container holding the registered fact producers (pack defaults are bypassed).</param>
    /// <param name="errorWriter">Writer the diagnostics + error context are appended to.</param>
    /// <returns>The compiled override plan, or <see langword="null"/> when translation/binding/loading failed.</returns>
    public static CompiledTrustPlan? LoadAndCompile(
        string pathOrUrl,
        IReadOnlyList<string> rawParams,
        IServiceProvider services,
        TextWriter errorWriter)
    {
        ArgumentNullException.ThrowIfNull(pathOrUrl);
        ArgumentNullException.ThrowIfNull(rawParams);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(errorWriter);

        if (!TryLoadText(pathOrUrl, errorWriter, out string text, out string sourceUri))
        {
            return null;
        }

        if (!TryParseParameters(rawParams, errorWriter, out Dictionary<string, JsonNode?> bindings))
        {
            return null;
        }

        var frontend = (services.GetService(typeof(CoseTpJsonFrontend)) as CoseTpJsonFrontend)
            ?? new CoseTpJsonFrontend();

        IFactRegistry? registry = services.GetService(typeof(IFactRegistry)) as IFactRegistry
            ?? AttributeDrivenFactRegistry.FromLoadedAssemblies();

        var capabilities = new FactCapabilities { AvailableFactIds = registry.AllFactIds };

        var ctx = new TrustPolicyTranslationContext
        {
            AvailableFacts = capabilities,
            AllowUnknownFacts = false,
        };

        TrustPolicyTranslationResult result = frontend.TranslateText(text, ctx, sourceUri);
        if (!result.IsSuccess || result.Spec is null)
        {
            WriteDiagnostics(result.Diagnostics, errorWriter);
            return null;
        }

        TrustPolicyTranslationResult bound = result.Bind(bindings);
        if (!bound.IsSuccess || bound.Spec is null)
        {
            WriteDiagnostics(bound.Diagnostics, errorWriter);
            return null;
        }

        return CompiledTrustPlanFromSpec.CompileFromSpec(bound.Spec, registry, services);
    }

    private static void WriteDiagnostics(IReadOnlyList<TrustPolicyTranslationDiagnostic> diagnostics, TextWriter errorWriter)
    {
        errorWriter.WriteLine(ClassStrings.ErrTrustPolicyTranslateFailed);
        foreach (TrustPolicyTranslationDiagnostic diag in diagnostics)
        {
            string sourceText = diag.Location?.Source ?? string.Empty;
            string line = string.IsNullOrEmpty(sourceText)
                ? string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyDiagnosticFormat, diag.Code, diag.Message)
                : string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyDiagnosticWithLocationFormat, diag.Code, diag.Message, sourceText);
            errorWriter.WriteLine(line);
        }
    }

    private static bool TryLoadText(string pathOrUrl, TextWriter errorWriter, out string text, out string sourceUri)
    {
        text = string.Empty;
        sourceUri = pathOrUrl;

        if (pathOrUrl.StartsWith(ClassStrings.SchemeHttp, StringComparison.OrdinalIgnoreCase)
            || pathOrUrl.StartsWith(ClassStrings.SchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var handler = new HttpClientHandler { AllowAutoRedirect = false };
                using var client = new HttpClient(handler) { Timeout = ClassStrings.HttpTimeout };
                text = client.GetStringAsync(pathOrUrl).GetAwaiter().GetResult();
                return true;
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or UriFormatException)
            {
                errorWriter.WriteLine(string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyHttpFailedFormat, pathOrUrl, ex.Message));
                return false;
            }
        }

        string filePath = pathOrUrl;
        if (filePath.StartsWith(ClassStrings.SchemeFile, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                filePath = new Uri(pathOrUrl).LocalPath;
            }
            catch (UriFormatException ex)
            {
                errorWriter.WriteLine(string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyFileNotFound, ex.Message));
                return false;
            }
        }

        try
        {
            text = File.ReadAllText(filePath, Encoding.UTF8);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or IOException or UnauthorizedAccessException)
        {
            errorWriter.WriteLine(string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyFileNotFound, filePath));
            return false;
        }

        sourceUri = string.Concat(ClassStrings.DocumentSourcePrefixFile, filePath.Replace(ClassStrings.PathSlashWindows, ClassStrings.PathSlashUnix));
        return true;
    }

    private static bool TryParseParameters(IReadOnlyList<string> rawParams, TextWriter errorWriter, out Dictionary<string, JsonNode?> bindings)
    {
        bindings = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);

        foreach (string raw in rawParams ?? Enumerable.Empty<string>())
        {
            int sep = raw.IndexOf(ClassStrings.ParamSeparator, StringComparison.Ordinal);
            if (sep <= 0)
            {
                errorWriter.WriteLine(string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyParamFormat, raw));
                return false;
            }

            string name = raw[..sep];
            string value = raw[(sep + 1)..];

            JsonNode? node;
            try
            {
                node = JsonNode.Parse(value);
            }
            catch (JsonException ex)
            {
                errorWriter.WriteLine(string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrTrustPolicyParamJsonFormat, name, ex.Message));
                return false;
            }

            bindings[name] = node;
        }

        return true;
    }
}
