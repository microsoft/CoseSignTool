// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

/// <summary>
/// A base class for validation of <see cref="CoseSign1Message"/> objects through a singly linked chain pattern.
/// </summary>
public abstract class CoseSign1MessageValidator
{
    /// <summary>
    /// Mocking .ctor
    /// </summary>
    protected CoseSign1MessageValidator() { }

    private CoseSign1MessageValidator? NextElementInternal;
    /// <summary>
    /// Gets or Sets the next <see cref="CoseSign1MessageValidator"/> in this chain.
    /// </summary>
    public virtual CoseSign1MessageValidator? NextElement
    {
        get => NextElementInternal;
        set
        {
            if (value == this)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "value cannot be the same class instance");
            }
            NextElementInternal = value;
        }
    }

    /// <summary>
    /// Attempts to validate the <see cref="CoseSign1Message"/> using the forward linked list of chain elements.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> that is provided.</param>
    /// <param name="validationResults">A list of all <see cref="List{CoseSign1ValidationResult}"/> validation results for this validation chain.</param>
    /// <returns>True when validation succeeds, false otherwise.</returns>
    public virtual bool TryValidate(CoseSign1Message message, out List<CoseSign1ValidationResult> validationResults)
    {
        validationResults = new List<CoseSign1ValidationResult>();

        try
        {
            // validate the chain based on this objects logic.
            validationResults = Validate(message);
        }
        catch (Exception ex)
        {
            // something unexpected happened.
            validationResults.Add(new CoseSign1ValidationResult(GetType(), ex)
            {
                ResultMessage = ex.Message,
                PassedValidation = false
            });
        }

        // return no results in the chain have failed.
        return validationResults.All(r => r.PassedValidation);
    }

    /// <summary>
    /// Publicly Validate the contents of a CoseSign1Message <see cref="CoseSign1Message"/> object and returns the results from all steps in the validation chain.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> that is provided.</param>
    /// <returns>Returns a list of all <see cref="List{CoseSign1ValidationResult}"/> validation results for this validation chain.</returns>
    public virtual List<CoseSign1ValidationResult> Validate(CoseSign1Message message)
    {
        List<CoseSign1ValidationResult> returnValue = new()
        {
            // validate the message
            ValidateMessage(message)
        };

        // Send the message down the chain.
        // TODO: This should probably be "while" instead of "if" -- test with a second validator in chain
        if (NextElement != null)
        {
            returnValue.AddRange(NextElement.Validate(message));
        }

        return returnValue;
    }

    /// <summary>
    /// An abstract method to provide message validation for the given<see cref="CoseSign1Message"/>
    /// Implementations should override to provide message validation logic.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to be validated.</param>
    /// <returns>A <see cref="CoseSign1ValidationResult"/> representing the validation result.</returns>
    protected abstract CoseSign1ValidationResult ValidateMessage(CoseSign1Message message);

    /// <summary>
    /// Returns a null validator that can be used as a place holder when a validator is expected.
    /// </summary>
    /// <returns>A null validator.</returns>
    public static CoseSign1MessageValidator None => new EmptyValidator();

    /// <summary>
    /// A placeholder CoseSign1MessageValidator that does not validate anything.
    /// </summary>
    public class EmptyValidator : CoseSign1MessageValidator
    {
        /// <summary>
        /// Returns an empty validation result.
        /// </summary>
        /// <param name="message">Any CoseSign1Message object.</param>
        /// <returns>An empty validation result.</returns>
        protected override CoseSign1ValidationResult ValidateMessage(CoseSign1Message message) => new(typeof(EmptyValidator));

        /// <summary>
        /// Does not validate anything.
        /// </summary>
        /// <param name="message">Any CoseSign1Message object.</param>
        /// <returns>An empty result list.</returns>
        public override List<CoseSign1ValidationResult> Validate(CoseSign1Message message) => new();

        /// <summary>
        /// Does not validate anything.
        /// </summary>
        /// <param name="message">Any CoseSign1Message object.</param>
        /// <param name="validationResults">Yields an empty result list.</param>
        /// <returns>True in all cases.</returns>
        public override bool TryValidate(CoseSign1Message message, out List<CoseSign1ValidationResult> validationResults)
        {
            validationResults = new();
            return true;
        }

        /// <summary>
        /// Returns null in all cases.
        /// </summary>
        public override CoseSign1MessageValidator? NextElement => null;
    }
}
