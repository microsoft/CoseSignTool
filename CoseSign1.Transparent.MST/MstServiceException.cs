// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;
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
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{GetType().FullName}: {Message}");

        if (ProblemDetails != null)
        {
            sb.AppendLine("  Problem Details:");
            if (ProblemDetails.Status.HasValue)
            {
                sb.AppendLine($"    Status: {ProblemDetails.Status}");
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Type))
            {
                sb.AppendLine($"    Type: {ProblemDetails.Type}");
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Title))
            {
                sb.AppendLine($"    Title: {ProblemDetails.Title}");
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Detail))
            {
                sb.AppendLine($"    Detail: {ProblemDetails.Detail}");
            }

            if (!string.IsNullOrEmpty(ProblemDetails.Instance))
            {
                sb.AppendLine($"    Instance: {ProblemDetails.Instance}");
            }

            if (ProblemDetails.Extensions is { Count: > 0 })
            {
                sb.AppendLine("    Extensions:");
                foreach (var ext in ProblemDetails.Extensions)
                {
                    sb.AppendLine($"      {ext.Key}: {ext.Value}");
                }
            }
        }

        if (InnerException != null)
        {
            sb.AppendLine($" ---> {InnerException}");
            sb.AppendLine("   --- End of inner exception stack trace ---");
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
            var contentType = response.Headers.ContentType;

            if (contentType?.Contains("cbor", StringComparison.OrdinalIgnoreCase) == true)
            {
                try
                {
                    var content = response.Content;
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
            : $"MST service returned HTTP {requestFailedException.Status}: {requestFailedException.Message}";

        return problemDetails != null
            ? new MstServiceException(errorMessage, problemDetails, requestFailedException)
            : new MstServiceException(errorMessage, requestFailedException);
    }

    /// <summary>
    /// Builds a human-readable error message from parsed problem details.
    /// </summary>
    private static string BuildErrorMessage(CborProblemDetails details, int httpStatus)
    {
        var parts = new System.Collections.Generic.List<string>
        {
            $"MST service returned an error (HTTP {details.Status ?? httpStatus})"
        };

        if (!string.IsNullOrEmpty(details.Title))
        {
            parts.Add($": {details.Title}");
        }

        if (!string.IsNullOrEmpty(details.Detail) && details.Detail != details.Title)
        {
            parts.Add($". {details.Detail}");
        }

        return string.Concat(parts);
    }
}