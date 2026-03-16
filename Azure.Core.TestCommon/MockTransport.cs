// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Core.Pipeline;
using System.Diagnostics.CodeAnalysis;

namespace Azure.Core.TestCommon;

/// <summary>
/// Mock HTTP pipeline transport for testing Azure SDK clients.
/// </summary>
/// <remarks>
/// From https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core.TestFramework/src/MockTransport.cs
/// </remarks>
[ExcludeFromCodeCoverage]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class MockTransport : HttpPipelineTransport
{
    private readonly object _syncObj = new();
    private readonly Func<HttpMessage, MockResponse>? _responseFactory;

    /// <summary>
    /// Gets the async gate for controlling request/response flow in tests.
    /// </summary>
    public AsyncGate<MockRequest, MockResponse>? RequestGate { get; }

    /// <summary>
    /// Gets the list of requests made through this transport.
    /// </summary>
    public List<MockRequest> Requests { get; } = new();

    /// <summary>
    /// Gets or sets whether to expect sync pipeline operations.
    /// </summary>
    public bool? ExpectSyncPipeline { get; set; }

    /// <summary>
    /// Creates a new instance using the async gate pattern.
    /// </summary>
    public MockTransport()
    {
        RequestGate = new AsyncGate<MockRequest, MockResponse>();
    }

    /// <summary>
    /// Creates a new instance with a sequence of canned responses.
    /// </summary>
    public MockTransport(params MockResponse[] responses)
    {
        int requestIndex = 0;
        _responseFactory = _ =>
        {
            lock (_syncObj)
            {
                return responses[requestIndex++];
            }
        };
    }

    /// <summary>
    /// Creates a new instance with a response factory function.
    /// </summary>
    public MockTransport(Func<MockRequest, MockResponse> responseFactory)
        : this(req => responseFactory((MockRequest)req.Request))
    {
    }

    private MockTransport(Func<HttpMessage, MockResponse> responseFactory)
    {
        _responseFactory = responseFactory;
    }

    /// <summary>
    /// Creates a mock transport from a message callback function.
    /// </summary>
    public static MockTransport FromMessageCallback(Func<HttpMessage, MockResponse> responseFactory)
        => new(responseFactory);

    /// <inheritdoc/>
    public override Request CreateRequest() => new MockRequest();

    /// <inheritdoc/>
    public override void Process(HttpMessage message)
    {
        if (ExpectSyncPipeline == false)
        {
            throw new InvalidOperationException("Sync pipeline invocation not expected");
        }

        ProcessCore(message).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public override async ValueTask ProcessAsync(HttpMessage message)
    {
        if (ExpectSyncPipeline == true)
        {
            throw new InvalidOperationException("Async pipeline invocation not expected");
        }

        await ProcessCore(message);
    }

    private async Task ProcessCore(HttpMessage message)
    {
        if (message.Request is not MockRequest request)
        {
            throw new InvalidOperationException("The request is not compatible with the transport");
        }

        message.Response = null!;

        lock (_syncObj)
        {
            Requests.Add(request);
        }

        if (RequestGate != null)
        {
            message.Response = await RequestGate.WaitForRelease(request);
        }
        else if (_responseFactory != null)
        {
            message.Response = _responseFactory(message);
        }

        message.Response.ClientRequestId = request.ClientRequestId;

        if (message.Response.ContentStream != null && ExpectSyncPipeline != null)
        {
            message.Response.ContentStream = new AsyncValidatingStream(!ExpectSyncPipeline.Value, message.Response.ContentStream);
        }
    }

    /// <summary>
    /// Gets the single request made through this transport.
    /// </summary>
    public MockRequest SingleRequest
    {
        get
        {
            lock (_syncObj)
            {
                return Requests.Single();
            }
        }
    }
}
#pragma warning restore CS1591
