# CoseSign1.Transparent Documentation  

## Overview  
The `CoseSign1.Transparent` project provides extensions to the `CoseSign1Message` class, enabling the creation and validation of transparent COSE (CBOR Object Signing and Encryption) messages. These extensions are designed to facilitate transparency registration and validation workflows, ensuring secure and traceable message handling.  

## Prerequisites  
Before using this library, ensure the following:  
- Your project targets `.NET Standard 2.0` or higher.  
- You have included the `CoseSign1.Transparent` package in your project.  
- You have access to the `CoseSign1.Abstractions` project, as it is referenced by this library.  

## Installation  
To use this library, add a reference to the `CoseSign1.Transparent` project in your solution. If using NuGet, ensure the package is installed:

```text
dotnet add package CoseSign1.Transparency
```
## Namespace
Include the following namesapces in your code:
```csharp
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.Interfaces;
```

## Features  
- **Transparent Message Creation**: Generate COSE messages with transparency metadata.  
- **Validation**: Validate COSE messages against transparency requirements.  

## Usage  
### 1. Creating a Transparent COSE Message  
To create a transparent COSE Sign1 message, use the `MakeTransparentAsync` method. This method embeds transparency metadata into the message.
#### <u>Example: Creating a Transparent Message:</u>
```csharp
using System;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
using CoseSign1.Transparent.Interfaces;
using CoseSign1.Transparent.MST;

public class TransparencyExample
{
    public async Task CreateTransparentMessage()
    {
        // Create a COSE Sign1 message (example payload)
        CoseSign1Message message = new CoseSign1Message
        {
            Content = new byte[] { 1, 2, 3, 4 }
        };

        // Initialize the transparency service (using Azure CTS as an example)
        CodeTransparencyClient transparencyClient = new CodeTransparencyClient();
        
        // Optional: Configure verification options for advanced receipt validation
        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = new List<string> { "trusted-cts.azure.com" },
            AuthorizedReceiptBehavior = AuthorizedReceiptBehavior.RequireAll,
            UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
        };
        
        ITransparencyService transparencyService = new MstTransparencyService(
            transparencyClient, 
            verificationOptions, 
            null);

        // Make the message transparent
        CoseSign1Message transparentMessage = await message.MakeTransparentAsync(transparencyService);

        Console.WriteLine("Transparent message created successfully.");
    }
}
```
### 2. Verifying Transparency  
To verify the transparency of a COSE Sign1 message, use the `VerifyTransparencyAsync` method. This ensures the message complies with transparency rules.
#### <u>Example: Verifying a Transparent Message with embedded receipt:</u>
```csharp
using System;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
using CoseSign1.Transparent.Interfaces;
using CoseSign1.Transparent.MST;

public class TransparencyExample
{
    public async Task VerifyTransparentMessage()
    {
        // Example COSE Sign1 message
        CoseSign1Message message = new CoseSign1Message
        {
            Content = new byte[] { 1, 2, 3, 4 }
        };

        // Initialize the transparency service
        ITransparencyService transparencyService = new CodeTransparencyClient().ToCoseSign1TransparentService();

        // Verify the transparency of the message
        bool isTransparent = await message.VerifyTransparencyAsync(transparencyService);

        Console.WriteLine($"Message transparency verification result: {isTransparent}");
    }
}
```
#### <u>Example: Verifying a Transparent Message without an embedded receipt:</u>
```csharp
using System;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
using CoseSign1.Transparent.Interfaces;
using CoseSign1.Transparent.MST;

public class TransparencyExample
{
    public async Task VerifyTransparentMessageWithReceipt()
    {
        // Example COSE Sign1 message
        CoseSign1Message message = new CoseSign1Message
        {
            Content = new byte[] { 1, 2, 3, 4 }
        };

        // Example receipt
        byte[] receipt = new byte[] { 5, 6, 7, 8 };

        // Initialize the transparency service
        ITransparencyService transparencyService = new CodeTransparencyClient().ToCoseSign1TransparentService();

        // Verify the transparency of the message with the receipt
        bool isTransparent = await message.VerifyTransparencyAsync(transparencyService, receipt);

        Console.WriteLine($"Message transparency verification with receipt result: {isTransparent}");
    }
}

```
### 3. Managing Receipts  
Receipts may embedded in the transparency-related headers of COSE Sign1 messages. You can extract or add receipts using the following methods:
#### <u>Extracting Receipts</u>
Use the `TryGetReceipts` method to extract receipts from a COSE Sign1 message.
```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.Extensions;

public class ReceiptExample
{
    public void ExtractReceipts()
    {
        // Example COSE Sign1 message
        CoseSign1Message message = new CoseSign1Message();

        // Extract receipts
        if (message.TryGetReceipts(out List<byte[]>? receipts))
        {
            Console.WriteLine("Receipts extracted successfully.");
        }
        else
        {
            Console.WriteLine("No receipts found.");
        }
    }
}
```
#### <u>Adding Receipts</u>
Use the `AddReceipts` method to add receipts to a COSE Sign1 message.
```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.Extensions;

public class ReceiptExample
{
    public void AddReceipts()
    {
        // Example COSE Sign1 message
        CoseSign1Message message = new CoseSign1Message();

        // Example receipts
        List<byte[]> receipts = new List<byte[]>
        {
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 }
        };

        // Add receipts to the message
        message.AddReceipts(receipts);

        Console.WriteLine("Receipts added successfully.");
    }
}
```
## Advanced Topics
### Transparency Header
The transparency header is identified by the `TransparencyHeaderLabel` field. This label is used to embed and retrieve transparency-related metadata.
```csharp
using CoseSign1.Transparent.Extensions;

Console.WriteLine($"Transparency Header Label: {CoseSign1TransparencyMessageExtensions.TransparencyHeaderLabel}");
```
### Custom Transparency Services
You can implement your own transparency service by creating a class that implements the `ITransparencyService` interface. This allows you to define custom behavior for creating and verifying transparent messages.

### Error Handling
#### Common Exceptions
- `InvalidOperationException`: Thrown when attempting to create or verify a transparent message without the necessary metadata.
- `ArgumentNullException`: Thrown when required parameters are null.

##### <b>Example:</b>
```csharp
try
{
    // Example usage
}
catch (ArgumentNullException ex)
{
    Console.WriteLine($"Argument null: {ex.ParamName}");
}
catch (InvalidOperationException ex)
{
    Console.WriteLine($"Invalid operation: {ex.Message}");
}

```
## Configuration  
The project is configured to enforce strict code quality and static analysis rules. Ensure your development environment supports the following:  
- Nullable reference types (`<Nullable>enable</Nullable>`).  
- Latest C# language features (`<LangVersion>latest</LangVersion>`).  

## Strong Name Signing  
The assembly is strong-name signed using the key file located at `..\StrongNameKeys\35MSSharedLib1024.snk`. Ensure your build environment has access to this key file.  

## Packaging  
The project is packaged with the following metadata:  
- License: `LICENSE`  
- Readme: `readme.md`  
- Release Notes: `ChangeLog.md`  

## Additional Resources  
- [COSE Specification](https://datatracker.ietf.org/doc/html/rfc8152)  
- [CBOR Specification](https://datatracker.ietf.org/doc/html/rfc7049)  

## Support  
For issues or feature requests, please contact the maintainers or open an issue in the repository.

## Conclusion
The `CoseSign1.Transparency`` library provides a robust solution for creating and verifying transparent COSE Sign1 messages. By embedding transparency metadata, you can ensure traceability and auditability in your software supply chain. For advanced scenarios, consider implementing custom transparency services or managing receipts programmatically.
<br/>
<br/>
For more information, refer to the ./docs/CoseSignTool.md.
