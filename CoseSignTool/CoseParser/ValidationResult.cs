// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

/// <summary>
/// Defines the result of a COSE signature validation attempt.
/// </summary>
public struct ValidationResult
{
    /// <summary>
    /// Creates a new ValidationResult object.
    /// </summary>
    /// <param name="errors">A list of CoseValidationError values representing individual errors, if any.</param>
    /// <param name="internalResults">A list of CoseSign1ValidationResult objects from internal validators, if any.</param>
    public ValidationResult(bool success, List<ValidationFailureCode>? errors, List<CoseSign1ValidationResult>? internalResults = null)
    {
        Success = success;
        Errors = ExpandErrors(errors);
        InnerResults = internalResults;
    }

    /// <summary>
    /// Indicates whether validation succeeded or not.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// The set of errors that caused validation to fail, if any.
    /// </summary>
    public List<CoseValidationError>? Errors { get; set; }

    /// <summary>
    /// The set of specific errors passed from the internal validator, if any.
    /// </summary>
    public List<CoseSign1ValidationResult>? InnerResults { get; set; }

    internal static List<CoseValidationError>? ExpandErrors(List<ValidationFailureCode>? errors)
    => errors?.Select(c => new CoseValidationError(c)).ToList();

    /// <summary>
    /// Adds an error to the <see cref="Errors"/> list.
    /// </summary>
    /// <param name="code"></param>
    public void AddError(ValidationFailureCode code)
    {
        Errors ??= new List<CoseValidationError>();
        Errors.Add(new CoseValidationError(code));
    }

    /// <summary>
    /// Returns a text summary of the validation result.
    /// </summary>
    /// <param name="verbose">True to include chain trust validation and exception messages in the error output.</param>
    /// <returns>A text summary of the validation result.</returns>
    public readonly string ToString(bool verbose = false)
    {
        string newline = Environment.NewLine;
        string tab = "    ";

        if (Success)
        {
            // Print success. If verbose, include any chain validation messages.
            return
                (verbose && InnerResults != null) ? $"Validation succeeded.{newline}{string.Join(newline, InnerResults.Select(r => r.ResultMessage))}" :
                $"Validation succeeded.";
        }

        // Validation failed, so build the error text.
        string header = $"Validation failed.{newline}=================================={newline}";
        string footer = $"{newline}Run validation in Verbose mode for more details.";

        // Format the errors into a block, with one error per line.
        string errorBlock = Errors?.Count switch
        {
            0 or null => CoseValidationError.ErrorMessages[ValidationFailureCode.Unknown],
            1 => Errors.FirstOrDefault().Message,
            _ => string.Join(newline, Errors.Select(e => e.Message))
        };

        if (!verbose)
        {
            // Print just the header and the top level error messages.
            return $"{header}{errorBlock}";
        }

        // We're in Verbose mode, so get all the Includes from the internal validators.
        IEnumerable<object>? allIncludes =
            InnerResults?
                .Where(r => r.Includes?.Count > 0 is true)?
                .SelectMany(r => r.Includes ?? new List<object>())
                .Distinct();

        // Now filter them down to just chain status errors.
        var certChainErrors = allIncludes?.Cast<X509ChainStatus>().Where(f => f.Status != X509ChainStatusFlags.NoError).ToList();
        string certChainBlock =
            certChainErrors?.Count > 0 ? $"Certificate chain status:{newline}{string.Join(newline + tab, certChainErrors.Select(c => c.StatusInformation))}" :
            string.Empty;

        // Do the same for exceptions.
        List<Exception>? innerExceptions = allIncludes?.Cast<Exception>().ToList();
        string exceptionBlock =
            innerExceptions?.Count > 0 ? $"Exceptions:{newline}{string.Join(newline + tab, innerExceptions.Select(e => $"{e.GetType()}: {e.Message}"))}" :
            string.Empty;

        // Return error messages, then cert chain errors, then exception messages.
        return $"{header}{errorBlock}{newline}{certChainBlock}{newline}{exceptionBlock}";
    }
}