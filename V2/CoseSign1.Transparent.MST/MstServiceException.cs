// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Text;

/// <summary>
/// Exception thrown when an MST transparency service operation fails.
/// </summary>
/// <remarks>
/// This exception captures parsed details from CBOR problem details responses
/// (<c>application/concise-problem-details+cbor</c>) as defined in RFC 9290,
/// when the Azure Code Transparency Service returns an error.
/// </remarks>
public class MstServiceException : Exception
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProblemDetailsHeader = "  Problem Details:";
        public const string StatusLineFormat = "    Status: {0}";
        public const string TypeLineFormat = "    Type: {0}";
        public const string TitleLineFormat = "    Title: {0}";
        public const string DetailLineFormat = "    Detail: {0}";
        public const string InstanceLineFormat = "    Instance: {0}";
        public const string ExtensionsHeader = "    Extensions:";
        public const string ExtensionLineFormat = "      {0}: {1}";
        public const string InnerExceptionFormat = " ---> {0}";
        public const string InnerExceptionEnd = "   --- End of inner exception stack trace ---";
        public const string CborContentTypeFragment = "cbor";
        public const string ExceptionHeaderFormat = "{0}: {1}";
        public const string GenericErrorFormat = "MST service returned HTTP {0}: {1}";
        public const string ProblemDetailsErrorPrefix = "MST service returned an error (HTTP {0})";
        public const string TitleSuffixFormat = ": {0}";
        public const string DetailSuffixFormat = ". {0}";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstServiceException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception, if any.</param>
    public MstServiceException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstServiceException"/> class with parsed problem details.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="problemDetails">The parsed CBOR problem details from the MST response.</param>
    /// <param name="innerException">The inner exception, if any.</param>
    public MstServiceException(
        string message,
        CborProblemDetails problemDetails,
        Exception? innerException = null)
        : base(message, innerException)
    {
        ProblemDetails = problemDetails;
    }

    /// <summary>
    /// Gets the HTTP status code from the failed request, if available from the problem details.
    /// </summary>
    public int? StatusCode => ProblemDetails?.Status;

    /// <summary>
    /// Gets the parsed CBOR problem details (RFC 9290) from the service response, if available.
    /// </summary>
    public CborProblemDetails? ProblemDetails { get; }

    /// <summary>
    /// Returns a detailed string representation including all parsed problem details.
    /// </summary>
    /// <returns>A formatted string with exception details, problem details, and inner exception information.</returns>
    public override string ToString()
    {
        StringBuilder sb = new();
        sb.AppendLine(string.Format(ClassStrings.ExceptionHeaderFormat, GetType().FullName, Message));

        if (ProblemDetails != null)
        {
            sb.AppendLine(ClassStrings.ProblemDetailsHeader);

            if (ProblemDetails.Status.HasValue)
            {
                sb.AppendLine(string.Format(ClassStrings.StatusLineFormat, ProblemDetails.Status));
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Type))
            {
                sb.AppendLine(string.Format(ClassStrings.TypeLineFormat, ProblemDetails.Type));
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Title))
            {
                sb.AppendLine(string.Format(ClassStrings.TitleLineFormat, ProblemDetails.Title));
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Detail))
            {
                sb.AppendLine(string.Format(ClassStrings.DetailLineFormat, ProblemDetails.Detail));
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Instance))
            {
                sb.AppendLine(string.Format(ClassStrings.InstanceLineFormat, ProblemDetails.Instance));
            }

            if (ProblemDetails.Extensions is { Count: > 0 })
            {
                sb.AppendLine(ClassStrings.ExtensionsHeader);
                foreach (KeyValuePair<string, object?> ext in ProblemDetails.Extensions)
                {
                    sb.AppendLine(string.Format(ClassStrings.ExtensionLineFormat, ext.Key, ext.Value));
                }
            }
        }

        if (InnerException != null)
        {
            sb.AppendLine(string.Format(ClassStrings.InnerExceptionFormat, InnerException));
            sb.AppendLine(ClassStrings.InnerExceptionEnd);
        }

        if (StackTrace != null)
        {
            sb.AppendLine(StackTrace);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Creates an <see cref="MstServiceException"/> from an Azure <see cref="Azure.RequestFailedException"/>,
    /// attempting to parse CBOR problem details from the response body.
    /// </summary>
    /// <param name="requestFailedException">The Azure SDK request failure.</param>
    /// <returns>An <see cref="MstServiceException"/> with parsed details when available.</returns>
    public static MstServiceException FromRequestFailedException(Azure.RequestFailedException requestFailedException)
    {
        CborProblemDetails? problemDetails = null;

        if (requestFailedException.GetRawResponse() is Azure.Response response)
        {
            string? contentType = response.Headers.ContentType;

            if (contentType?.Contains(ClassStrings.CborContentTypeFragment, StringComparison.OrdinalIgnoreCase) == true)
            {
                try
                {
                    BinaryData? content = response.Content;
                    if (content != null && content.ToMemory().Length > 0)
                    {
                        problemDetails = CborProblemDetails.TryParse(content.ToArray());
                    }
                }
                catch (CborContentException)
                {
                    // CBOR parsing failure is non-fatal; fall through to generic message
                }
                catch (InvalidOperationException)
                {
                    // Parsing state failure is non-fatal; fall through to generic message
                }
            }
        }

        string errorMessage = problemDetails != null
            ? BuildErrorMessage(problemDetails, requestFailedException.Status)
            : string.Format(ClassStrings.GenericErrorFormat, requestFailedException.Status, requestFailedException.Message);

        return problemDetails != null
            ? new MstServiceException(errorMessage, problemDetails, requestFailedException)
            : new MstServiceException(errorMessage, requestFailedException);
    }

    private static string BuildErrorMessage(CborProblemDetails details, int httpStatus)
    {
        List<string> parts = new()
        {
            string.Format(ClassStrings.ProblemDetailsErrorPrefix, details.Status ?? httpStatus)
        };

        if (!string.IsNullOrEmpty(details.Title))
        {
            parts.Add(string.Format(ClassStrings.TitleSuffixFormat, details.Title));
        }

        if (!string.IsNullOrEmpty(details.Detail) && details.Detail != details.Title)
        {
            parts.Add(string.Format(ClassStrings.DetailSuffixFormat, details.Detail));
        }

        return string.Concat(parts);
    }
}