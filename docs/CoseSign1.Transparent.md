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
dotnet add package CoseSign1.Transparent
```
## Namespace
Include the following namespaces in your code:
```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.MST;
```

> **Note:** Extension methods on `CodeTransparencyClient` and `CodeTransparencyClientOptions`
> are placed in the `Azure.Security.CodeTransparency` namespace and are available automatically
> without any additional `using` statements.

## Features  
- **Transparent Message Creation**: Register a message with a transparency service and embed receipts.
- **Verification**: Verify embedded receipts (and/or specific receipts) against a transparency service.
- **TransactionNotCached Fast Retry**: Automatic aggressive retry for the MST `GetEntryStatement` 503 pattern.
- **Polling Options**: Configurable polling intervals and custom delay strategies for long-running operations.
- **CBOR Problem Details**: RFC 9290 error parsing for MST service error responses.

## Usage

This library uses the abstract base class `TransparencyService` as the single service abstraction (the previous `ITransparencyService` interface is not used).

### 1. Creating a Transparent COSE Message
To create a transparent COSE Sign1 message, use `MakeTransparentAsync`.

#### <u>Example: Creating a Transparent Message</u>
```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.MST;

public class TransparencyExample
{
    public async Task CreateTransparentMessage(CodeTransparencyClient transparencyClient)
    {
        CoseSign1Message message = new CoseSign1Message
        {
            Content = new byte[] { 1, 2, 3, 4 }
        };

        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = new List<string> { "trusted-cts.azure.com" },
            AuthorizedReceiptBehavior = AuthorizedReceiptBehavior.RequireAll,
            UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
        };

        TransparencyService transparencyService = new MstTransparencyService(
            transparencyClient,
            verificationOptions,
            clientOptions: null);

        CoseSign1Message transparentMessage = await message.MakeTransparentAsync(transparencyService);

        Console.WriteLine("Transparent message created successfully.");
    }
}
```

#### <u>Example: Creating a Transparent Message with Polling Options</u>
```csharp
using Azure.Core;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.MST;

public class TransparencyWithPollingExample
{
    public async Task CreateTransparentMessageWithPolling(Uri endpoint, AzureKeyCredential credential)
    {
        CoseSign1Message message = new CoseSign1Message { Content = new byte[] { 1, 2, 3 } };

        // Configure client options with pipeline policy for fast /entries/ retries
        var clientOptions = new CodeTransparencyClientOptions();
        clientOptions.ConfigureMstPerformanceOptimizations();

        // Create client WITH configured options (pipeline is frozen at construction)
        var client = new CodeTransparencyClient(endpoint, credential, clientOptions);

        // Use DelayStrategy (not PollingInterval) for sub-second LRO polling
        var pollingOptions = new MstPollingOptions
        {
            DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(100))
        };

        // Extension method with polling options — no extra 'using' needed
        TransparencyService service = client.ToCoseSign1TransparencyService(
            pollingOptions,
            logVerbose: Console.WriteLine);

        CoseSign1Message result = await message.MakeTransparentAsync(service);
    }
}
```

### 2. Verifying Transparency
To verify transparency for a COSE Sign1 message, use `VerifyTransparencyAsync`.

#### <u>Example: Verifying a Transparent Message with Embedded Receipt(s)</u>
```csharp
using System;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;
using CoseSign1.Transparent.Extensions;

public class TransparencyExample
{
    public async Task VerifyTransparentMessage(CodeTransparencyClient transparencyClient, CoseSign1Message message)
    {
        TransparencyService transparencyService = transparencyClient.ToCoseSign1TransparencyService();

        bool isTransparent = await message.VerifyTransparencyAsync(transparencyService);

        Console.WriteLine($"Message transparency verification result: {isTransparent}");
    }
}
```

#### <u>Example: Verifying with a Specific Receipt</u>
```csharp
using System;
using System.Security.Cryptography.Cose;
using System.Threading.Tasks;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;

public class TransparencyExample
{
    public async Task VerifyTransparentMessageWithReceipt(CodeTransparencyClient transparencyClient, CoseSign1Message message, byte[] receipt)
    {
        TransparencyService transparencyService = transparencyClient.ToCoseSign1TransparencyService();

        bool isTransparent = await transparencyService.VerifyTransparencyAsync(message, receipt);

        Console.WriteLine($"Message transparency verification with receipt result: {isTransparent}");
    }
}
```
### 3. Managing Receipts  
Receipts may be embedded in the transparency-related headers of COSE Sign1 messages. You can extract or add receipts using the following methods:
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

Notes:
- `AddReceipts` merges with any existing embedded receipts and deduplicates by exact byte-content (not by reference).
- Null or empty receipts are ignored; if no valid receipts remain after filtering, an exception is thrown.
## Advanced Topics
### Transparency Header
The transparency header is identified by the `TransparencyHeaderLabel` field. This label is used to embed and retrieve transparency-related metadata.
```csharp
using CoseSign1.Transparent.Extensions;

Console.WriteLine($"Transparency Header Label: {CoseSign1TransparencyMessageExtensions.TransparencyHeaderLabel}");
```

### Receipt Preservation When Chaining Services
Some transparency services may return a *new* `CoseSign1Message` instance (rather than mutating the input message). When calling `MakeTransparentAsync`, this library preserves any existing embedded receipts and merges them into the returned message.

This is especially important when chaining multiple transparency services (e.g., registering with multiple systems). Receipt merging is stable-order (existing receipts first) and deduplicated by byte-content.

### Custom Transparency Services
You can implement your own transparency service by deriving from the `TransparencyService` base class. It automatically:
- Preserves and merges existing receipts into the returned message.
- Provides optional logging hooks for basic diagnostics (timings and receipt counts).

#### <u>Example: Deriving from `TransparencyService`</u>
```csharp
using System;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Transparent;

public sealed class MyTransparencyService : TransparencyService
{
    public MyTransparencyService(
        Action<string>? logVerbose = null,
        Action<string>? logWarning = null,
        Action<string>? logError = null)
        : base(logVerbose, logWarning, logError)
    {
    }

    protected override Task<CoseSign1Message> MakeTransparentCoreAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        // Register message, embed receipts (or return a new message instance).
        return Task.FromResult(message);
    }

    protected override Task<bool> VerifyTransparencyCoreAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        => Task.FromResult(true);

    protected override Task<bool> VerifyTransparencyWithReceiptCoreAsync(CoseSign1Message message, byte[] receipt, CancellationToken cancellationToken = default)
        => Task.FromResult(true);
}
```

#### <u>Example: Wiring Logging Hooks</u>
```csharp
var service = new MyTransparencyService(
    logVerbose: Console.WriteLine,
    logWarning: Console.Error.WriteLine,
    logError: Console.Error.WriteLine);
```

### Error Handling
#### Common Exceptions
- `InvalidOperationException`: Thrown when attempting to create or verify a transparent message without the necessary metadata.
- `ArgumentNullException`: Thrown when required parameters are null.
- `MstServiceException`: Thrown when the MST service returns an error. Includes parsed CBOR problem details (RFC 9290) when available.

##### <b>Example: Catching MstServiceException</b>
```csharp
try
{
    var result = await message.MakeTransparentAsync(transparencyService);
}
catch (MstServiceException ex)
{
    Console.WriteLine($"MST error: {ex.Message}");
    if (ex.ProblemDetails != null)
    {
        Console.WriteLine($"  Status: {ex.StatusCode}");
        Console.WriteLine($"  Detail: {ex.ProblemDetails.Detail}");
    }
}
catch (InvalidOperationException ex)
{
    Console.WriteLine($"Invalid operation: {ex.Message}");
}
```

### MST Performance Optimization

The Azure Code Transparency Service has two default behaviors that introduce unnecessary
1-second delays. Without optimization, each signing operation can take **2–3 seconds longer**
than necessary:

| Delay Source | Default Behavior | Impact |
|---|---|---|
| **LRO polling** | Azure SDK's `Operation<T>.WaitForCompletionAsync` uses an internal `FixedDelayWithNoJitterStrategy` that clamps any interval to `Max(suggestedDelay, 1 second)`, and the server returns `Retry-After: 1` headers that override client-configured intervals. | ~1 second per poll instead of ~100 ms |
| **Entry retrieval** | `GetEntryStatementAsync` returns HTTP 503 with `Retry-After: 1` when the entry hasn't propagated yet (typically available in < 100 ms). The SDK's default `RetryPolicy` respects this header and waits 1 second before retrying. | ~1 second delay on entry fetch |

#### <u>⚡ Best Practice: Configure Both Optimizations Together</u>

To achieve optimal performance, you **must** configure both:
1. A custom `DelayStrategy` on `MstPollingOptions` to bypass the SDK's 1-second LRO polling floor
2. The `MstPerformanceOptimizationPolicy` on `CodeTransparencyClientOptions` to fast-retry 503 responses

> **Critical:** The `CodeTransparencyClientOptions` with the policy must be passed to the
> `CodeTransparencyClient` constructor — that is when the HTTP pipeline is built. Adding the
> policy to options *after* the client is constructed has no effect on that client's pipeline.

```csharp
using Azure.Core;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;

// 1. Configure client options with the performance optimization pipeline policy
var clientOptions = new CodeTransparencyClientOptions();
clientOptions.ConfigureMstPerformanceOptimizations();  // fast-retries 503s on /entries/

// 2. Create the client WITH the configured options (pipeline is built here)
var client = new CodeTransparencyClient(endpoint, credential, clientOptions);

// 3. Configure polling options with a custom DelayStrategy for fast LRO polling
var pollingOptions = new MstPollingOptions
{
    DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(100))
};

// 4. Create the transparency service with both the client and options
var service = new MstTransparencyService(
    client,
    verificationOptions,
    clientOptions,      // used by VerifyTransparentStatement (static method creates new clients)
    pollingOptions);

// Now both MakeTransparentAsync and VerifyTransparencyAsync are optimized
CoseSign1Message result = await service.MakeTransparentAsync(message);
```

> **Without these optimizations:** A typical signing + entry retrieval takes ~3.5 seconds.
> **With both optimizations:** The same operation completes in ~1.0–1.5 seconds.

#### <u>What Each Optimization Does</u>

**`MstPollingOptions.DelayStrategy`** — Controls LRO polling interval:
- The Azure SDK's internal delay strategy enforces a 1-second floor on polling intervals
- Using `DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(100))` bypasses this
  by passing the strategy directly to `Operation<T>.WaitForCompletionAsync(DelayStrategy, ...)`
- This takes precedence over `PollingInterval` if both are set

**`ConfigureMstPerformanceOptimizations()`** — Adds a pipeline policy that:
- Intercepts HTTP 503 responses on `/entries/` endpoints and retries at 250 ms intervals
  (up to 8 retries ≈ 2 seconds) before the SDK's `RetryPolicy` sees the error
- Strips `Retry-After`, `retry-after-ms`, and `x-ms-retry-after-ms` headers from both
  `/entries/` and `/operations/` responses to prevent the SDK from overriding client timing

#### <u>Custom Retry Settings</u>
```csharp
var options = new CodeTransparencyClientOptions();
options.ConfigureMstPerformanceOptimizations(
    retryDelay: TimeSpan.FromMilliseconds(100),  // faster polling
    maxRetries: 16);                              // longer window
```

#### <u>Manual Policy Registration</u>
```csharp
using Azure.Core.Pipeline;

var options = new CodeTransparencyClientOptions();
options.AddPolicy(
    new MstPerformanceOptimizationPolicy(TimeSpan.FromMilliseconds(200), 10),
    HttpPipelinePosition.PerRetry);
```

> **Important:** Use `HttpPipelinePosition.PerRetry` so the policy runs inside the SDK's retry
> loop and above the tracing layer (`RequestActivityPolicy`). This ensures fast retries are
> visible in distributed traces (e.g., OpenTelemetry / Aspire). The extension method
> `ConfigureMstPerformanceOptimizations` handles this automatically.

#### <u>Diagnostic Tracing</u>

The policy emits `System.Diagnostics.Activity` spans via an `ActivitySource` named
`CoseSign1.Transparent.MST.PerformanceOptimizationPolicy`. When an OpenTelemetry collector
or Aspire dashboard is configured, you will see:

- **`MstPerformanceOptimization.Evaluate`** — emitted for every request through the policy,
  with tags showing the URL, method, status code, and action taken
- **`MstPerformanceOptimization.AcceleratedRetry`** — emitted when a 503 triggers the fast
  retry loop, with tags for attempt count, delay, and final status
- **`MstPerformanceOptimization.RetryAttempt`** — emitted per retry attempt within the loop

### Polling Options

The `MstPollingOptions` class controls how `MstTransparencyService` polls for completed
receipt registrations after `CreateEntryAsync`.

> **Important:** Use `DelayStrategy` (not `PollingInterval`) for sub-second polling.
> The Azure SDK's internal `FixedDelayWithNoJitterStrategy` clamps any interval to
> `Max(suggestedDelay, 1 second)`, making `PollingInterval` values below 1 second ineffective.
> `DelayStrategy` bypasses this by passing directly to
> `Operation<T>.WaitForCompletionAsync(DelayStrategy, CancellationToken)`.

#### <u>Recommended: Fixed Delay Strategy (sub-second polling)</u>
```csharp
using Azure.Core;

var pollingOptions = new MstPollingOptions
{
    DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(100))
};
var service = new MstTransparencyService(client, pollingOptions);
```

#### <u>Fixed Interval Polling (1 second minimum)</u>
```csharp
var pollingOptions = new MstPollingOptions
{
    PollingInterval = TimeSpan.FromSeconds(2)
};
var service = new MstTransparencyService(client, pollingOptions);
```

#### <u>Via Extension Method</u>
```csharp
TransparencyService service = client.ToCoseSign1TransparencyService(
    pollingOptions,
    logVerbose: Console.WriteLine,
    logError: Console.Error.WriteLine);
```

#### <u>Custom Delay Strategy</u>
```csharp
using Azure.Core;

var pollingOptions = new MstPollingOptions
{
    DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(500))
};
```

> If both `DelayStrategy` and `PollingInterval` are set, `DelayStrategy` takes precedence.

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
The `CoseSign1.Transparent` library provides a robust solution for creating and verifying transparent COSE Sign1 messages. By embedding transparency metadata, you can ensure traceability and auditability in your software supply chain. For advanced scenarios, consider implementing custom transparency services or managing receipts programmatically.
<br/>
<br/>
For more information, refer to the ./docs/CoseSignTool.md.
