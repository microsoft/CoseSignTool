// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Example: Using MstReceiptValidator to validate embedded MST receipts
//
// This example demonstrates how to use the MstReceiptValidator to verify
// that a COSE Sign1 message contains a valid MST (Microsoft Signing Transparency)
// receipt and that the receipt validates against the MST service.

using System;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
// using Azure.Identity;  // Uncomment when Azure.Identity is available
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;

namespace CoseSign1.Transparent.MST.Examples;

public static class MstReceiptValidatorExample
{
    /// <summary>
    /// Example 1: Basic MST receipt validation
    /// </summary>
    public static async Task BasicValidation()
    {
        // Setup: Create MST client
        // var credential = new DefaultAzureCredential();  // Uncomment when Azure.Identity is available
        var mstClient = new CodeTransparencyClient(
            new Uri("https://your-mst-instance.azure.net"));
        // credential);  // Uncomment when Azure.Identity is available

        // Create validator
        var validator = new MstReceiptValidator(mstClient);

        // Assume we have a message with an MST receipt
        CoseSign1Message message = GetMessageWithMstReceipt();

        // Validate the receipt
        var result = await validator.ValidateAsync(message);

        if (result.IsValid)
        {
            Console.WriteLine("✓ MST receipt is valid!");

            // Access validation metadata
            if (result.Metadata.ContainsKey("ProviderName"))
            {
                Console.WriteLine($"  Provider: {result.Metadata["ProviderName"]}");
            }
            if (result.Metadata.ContainsKey("verified"))
            {
                Console.WriteLine($"  Verified: {result.Metadata["verified"]}");
            }
        }
        else
        {
            Console.WriteLine("✗ MST receipt validation failed:");
            foreach (var failure in result.Failures)
            {
                Console.WriteLine($"  - {failure.Message}");
                if (failure.ErrorCode != null)
                {
                    Console.WriteLine($"    Error Code: {failure.ErrorCode}");
                }
            }
        }
    }

    /// <summary>
    /// Example 2: Validation with custom verification options
    /// </summary>
    public static async Task ValidationWithOptions()
    {
        // var credential = new DefaultAzureCredential();  // Uncomment when Azure.Identity is available
        var mstClient = new CodeTransparencyClient(
            new Uri("https://your-mst-instance.azure.net"));
        // credential);  // Uncomment when Azure.Identity is available

        // Configure verification behavior
        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            // Only accept receipts from these authorized domains
            AuthorizedDomains = new[] { "contoso.com", "fabrikam.com" }.ToList()

            // Require receipts from authorized domains
            // AuthorizedReceiptBehavior = ReceiptValidationBehavior.Require,  // TODO: Check actual API

            // Allow but don't require receipts from other domains
            // UnauthorizedReceiptBehavior = ReceiptValidationBehavior.Allow  // TODO: Check actual API
        };

        // Create validator with options
        var validator = new MstReceiptValidator(mstClient, verificationOptions);

        CoseSign1Message message = GetMessageWithMstReceipt();
        var result = await validator.ValidateAsync(message);

        if (result.IsValid)
        {
            Console.WriteLine("✓ MST receipt validated with policy compliance");
        }
        else
        {
            Console.WriteLine("✗ MST receipt failed policy requirements:");
            foreach (var failure in result.Failures)
            {
                Console.WriteLine($"  - {failure.Message}");
            }
        }
    }

    /// <summary>
    /// Example 3: Composing validators for comprehensive validation
    /// </summary>
    public static async Task CompositeValidation()
    {
        // Setup MST validator
        // var credential = new DefaultAzureCredential();  // Uncomment when Azure.Identity is available
        var mstClient = new CodeTransparencyClient(
            new Uri("https://your-mst-instance.azure.net"));
        // credential);  // Uncomment when Azure.Identity is available
        var mstValidator = new MstReceiptValidator(mstClient);

        // Combine with other validators (example - not all types may be available)
        var validators = new CoseSign1.Validation.IValidator<CoseSign1Message>[]
        {
            // Add signature validator (from CoseSign1.Validation)
            // new SignatureValidator(),
            
            // Add certificate chain validator (from CoseSign1.Certificates.Validation)
            // new CertificateChainValidator(),
            
            // Add MST receipt validator
            mstValidator
        };

        // Create composite validator
        var compositeValidator = new CoseSign1.Validation.CompositeValidator(validators);

        CoseSign1Message message = GetMessageWithMstReceipt();
        var result = await compositeValidator.ValidateAsync(message);

        if (result.IsValid)
        {
            Console.WriteLine("✓ All validations passed!");
        }
        else
        {
            Console.WriteLine($"✗ Validation failed at: {result.ValidatorName}");
            foreach (var failure in result.Failures)
            {
                Console.WriteLine($"  - {failure.Message}");
            }
        }
    }

    /// <summary>
    /// Example 4: Handling messages without MST receipts
    /// </summary>
    public static async Task HandleMissingReceipt()
    {
        // var credential = new DefaultAzureCredential();  // Uncomment when Azure.Identity is available
        var mstClient = new CodeTransparencyClient(
            new Uri("https://your-mst-instance.azure.net"));
        // credential);  // Uncomment when Azure.Identity is available
        var validator = new MstReceiptValidator(mstClient);

        // Message without MST receipt
        CoseSign1Message messageWithoutReceipt = GetMessageWithoutMstReceipt();

        var result = await validator.ValidateAsync(messageWithoutReceipt);

        if (!result.IsValid)
        {
            // Expected: validation fails because no receipt present
            var failure = result.Failures[0];
            if (failure.ErrorCode == "MST_NO_RECEIPT")
            {
                Console.WriteLine("Expected: Message doesn't have MST receipt");
                Console.WriteLine("Consider making this message transparent first");
            }
        }
    }

    /// <summary>
    /// Example 5: Exception handling
    /// </summary>
    public static async Task ExceptionHandling()
    {
        // var credential = new DefaultAzureCredential();  // Uncomment when Azure.Identity is available
        var mstClient = new CodeTransparencyClient(
            new Uri("https://your-mst-instance.azure.net"));
        // credential);  // Uncomment when Azure.Identity is available
        var validator = new MstReceiptValidator(mstClient);

        try
        {
            CoseSign1Message message = GetMessageWithMstReceipt();
            var result = await validator.ValidateAsync(message);

            // Validator catches exceptions internally and returns them as failures
            if (!result.IsValid)
            {
                foreach (var failure in result.Failures)
                {
                    if (failure.Exception != null)
                    {
                        Console.WriteLine($"Validation exception: {failure.Exception.GetType().Name}");
                        Console.WriteLine($"Message: {failure.Message}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // ValidateAsync should not throw - it returns failures instead
            Console.WriteLine($"Unexpected exception: {ex.Message}");
        }
    }

    // Helper methods (would be replaced with actual message loading in real code)
    private static CoseSign1Message GetMessageWithMstReceipt()
    {
        // In real code, load from file or receive from network
        throw new NotImplementedException("Load actual message with MST receipt");
    }

    private static CoseSign1Message GetMessageWithoutMstReceipt()
    {
        // In real code, load from file or receive from network
        throw new NotImplementedException("Load actual message without MST receipt");
    }
}