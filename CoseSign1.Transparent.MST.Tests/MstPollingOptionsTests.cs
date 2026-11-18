// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Tests;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Interfaces;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.Extensions;
using Moq;

/// <summary>
/// Unit tests for <see cref="MstPollingOptions"/> and the polling behavior of
/// <see cref="MstTransparencyService"/>.
/// </summary>
[TestFixture]
public class MstPollingOptionsTests
{
    private CoseSign1MessageFactory? messageFactory;
    private ICoseSigningKeyProvider? signingKeyProvider;

    [SetUp]
    public void Setup()
    {
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();
        signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);
        messageFactory = new();
    }

    #region MstPollingOptions property tests

    /// <summary>
    /// Verifies that a newly created <see cref="MstPollingOptions"/> has null defaults.
    /// </summary>
    [Test]
    public void MstPollingOptions_DefaultsAreNull()
    {
        // Arrange & Act
        MstPollingOptions options = new();

        // Assert
        Assert.That(options.PollingInterval, Is.Null);
        Assert.That(options.DelayStrategy, Is.Null);
    }

    /// <summary>
    /// Verifies that <see cref="MstPollingOptions.PollingInterval"/> can be set and retrieved.
    /// </summary>
    [Test]
    public void MstPollingOptions_PollingInterval_CanBeSet()
    {
        // Arrange
        MstPollingOptions options = new();

        // Act
        options.PollingInterval = TimeSpan.FromSeconds(2);

        // Assert
        Assert.That(options.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(2)));
    }

    /// <summary>
    /// Verifies that <see cref="MstPollingOptions.DelayStrategy"/> can be set and retrieved.
    /// </summary>
    [Test]
    public void MstPollingOptions_DelayStrategy_CanBeSet()
    {
        // Arrange
        MstPollingOptions options = new();
        DelayStrategy strategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(500));

        // Act
        options.DelayStrategy = strategy;

        // Assert
        Assert.That(options.DelayStrategy, Is.SameAs(strategy));
    }

    /// <summary>
    /// Verifies that both properties can be set simultaneously.
    /// </summary>
    [Test]
    public void MstPollingOptions_BothPropertiesCanBeSet()
    {
        // Arrange & Act
        MstPollingOptions options = new()
        {
            PollingInterval = TimeSpan.FromSeconds(1),
            DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(200))
        };

        // Assert
        Assert.That(options.PollingInterval, Is.Not.Null);
        Assert.That(options.DelayStrategy, Is.Not.Null);
    }

    #endregion

    #region Constructor tests with MstPollingOptions

    /// <summary>
    /// Verifies the two-parameter constructor (client + pollingOptions) creates an instance.
    /// </summary>
    [Test]
    public void Constructor_WithPollingOptions_CreatesInstance()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        MstPollingOptions pollingOptions = new()
        {
            PollingInterval = TimeSpan.FromSeconds(1)
        };

        // Act
        MstTransparencyService service = new(mockClient, pollingOptions);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    /// <summary>
    /// Verifies the constructor with null pollingOptions creates an instance (defaults to SDK behavior).
    /// </summary>
    [Test]
    public void Constructor_WithNullPollingOptions_CreatesInstance()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();

        // Act
        MstTransparencyService service = new(mockClient, (MstPollingOptions?)null!);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    /// <summary>
    /// Verifies the four-parameter constructor (client, verificationOptions, clientOptions, pollingOptions).
    /// </summary>
    [Test]
    public void Constructor_WithVerificationAndPollingOptions_CreatesInstance()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        CodeTransparencyVerificationOptions verificationOptions = new()
        {
            AuthorizedDomains = { "example.com" }
        };
        MstPollingOptions pollingOptions = new()
        {
            PollingInterval = TimeSpan.FromMilliseconds(500)
        };

        // Act
        MstTransparencyService service = new(mockClient, verificationOptions, null, pollingOptions);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    /// <summary>
    /// Verifies the full constructor with all parameters including pollingOptions and logging.
    /// </summary>
    [Test]
    public void Constructor_WithAllOptionsAndLogging_CreatesInstance()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();
        MstPollingOptions pollingOptions = new()
        {
            DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(100))
        };
        List<string> logMessages = new();

        // Act
        MstTransparencyService service = new(
            mockClient,
            null,
            null,
            pollingOptions,
            null,
            msg => logMessages.Add($"VERBOSE: {msg}"),
            msg => logMessages.Add($"WARNING: {msg}"),
            msg => logMessages.Add($"ERROR: {msg}"));

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    /// <summary>
    /// Verifies that the original 6-parameter constructor (without pollingOptions) still works.
    /// </summary>
    [Test]
    public void Constructor_OriginalSixParameterOverload_StillWorks()
    {
        // Arrange
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();

        // Act
        MstTransparencyService service = new(
            mockClient, null, null,
            msg => { }, msg => { }, msg => { });

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    /// <summary>
    /// Verifies that the pollingOptions constructor still throws for null client.
    /// </summary>
    [Test]
    public void Constructor_WithPollingOptions_ThrowsForNullClient()
    {
        // Arrange
        MstPollingOptions pollingOptions = new() { PollingInterval = TimeSpan.FromSeconds(1) };

        // Act & Assert
        Assert.That(
            () => new MstTransparencyService(null!, pollingOptions),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("transparencyClient"));
    }

    #endregion

    #region MakeTransparentAsync with polling options

    /// <summary>
    /// Verifies that MakeTransparentAsync waits for commit and still succeeds for every polling configuration,
    /// since commit polling is now handled by the CodeTransparencyClient pipeline.
    /// </summary>
    [TestCase(false, false)]
    [TestCase(true, false)]
    [TestCase(false, true)]
    [TestCase(true, true)]
    public async Task MakeTransparentAsync_WaitsForCommit_RegardlessOfPollingOptions(bool setInterval, bool setStrategy)
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = CreateSuccessfulClient(out CoseSign1Message message);
        MstPollingOptions pollingOptions = new()
        {
            PollingInterval = setInterval ? TimeSpan.FromMilliseconds(100) : null,
            DelayStrategy = setStrategy ? DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(50)) : null
        };
        MstTransparencyService service = new(mockClient.Object, pollingOptions);

        // Act
        CoseSign1Message result = await service.MakeTransparentAsync(message);

        // Assert
        Assert.That(result, Is.Not.Null);
        mockClient.Verify(
            c => c.CreateEntryAsync(It.IsAny<BinaryData>(), true, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that a verbose message explains that configured polling options are ignored.
    /// </summary>
    [Test]
    public async Task MakeTransparentAsync_LogsPollingOptionsIgnored_WhenOptionsSet()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = CreateSuccessfulClient(out CoseSign1Message message);
        List<string> logMessages = new();
        MstPollingOptions pollingOptions = new()
        {
            PollingInterval = TimeSpan.FromMilliseconds(250)
        };
        MstTransparencyService service = new(
            mockClient.Object, null, null, pollingOptions,
            null, msg => logMessages.Add(msg), null, null);

        // Act
        await service.MakeTransparentAsync(message);

        // Assert
        Assert.That(logMessages, Has.Some.Contains("MstPollingOptions are ignored"));
    }

    /// <summary>
    /// Verifies that no polling message is logged when no polling options are configured.
    /// </summary>
    [Test]
    public async Task MakeTransparentAsync_DoesNotLogPollingOptions_WhenOptionsAllNull()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = CreateSuccessfulClient(out CoseSign1Message message);
        List<string> logMessages = new();
        MstTransparencyService service = new(
            mockClient.Object, null, null, new MstPollingOptions(),
            null, msg => logMessages.Add(msg), null, null);

        // Act
        await service.MakeTransparentAsync(message);

        // Assert
        Assert.That(logMessages, Has.None.Contains("MstPollingOptions"));
    }

    #endregion

    #region ServiceEndpoint auto-derivation tests

    /// <summary>
    /// Verifies that ServiceEndpoint is auto-derived from CodeTransparencyClient when not explicitly provided.
    /// </summary>
    [Test]
    public void ServiceEndpoint_IsDerivedFromClient_WhenNotExplicitlyProvided()
    {
        // Arrange — create a real CodeTransparencyClient with a known endpoint
        Uri expectedEndpoint = new("https://my-cts-instance.confidential-ledger.azure.com");
        CodeTransparencyClient client = new(expectedEndpoint);

        // Act
        MstTransparencyService service = new(client);

        // Assert — the endpoint should have been extracted via reflection
        Assert.That(service.ServiceEndpoint, Is.EqualTo(expectedEndpoint));
    }

    /// <summary>
    /// Verifies that an explicit serviceEndpoint overrides the auto-derived one.
    /// </summary>
    [Test]
    public void ServiceEndpoint_ExplicitOverridesAutoDerived()
    {
        // Arrange
        Uri clientEndpoint = new("https://auto-derived.example.com");
        Uri explicitEndpoint = new("https://explicit-override.example.com");
        CodeTransparencyClient client = new(clientEndpoint);

        // Act
        MstTransparencyService service = new(client, explicitEndpoint);

        // Assert
        Assert.That(service.ServiceEndpoint, Is.EqualTo(explicitEndpoint));
    }

    /// <summary>
    /// Verifies that ServiceEndpoint is null when using a mocked client (no _endpoint field).
    /// </summary>
    [Test]
    public void ServiceEndpoint_IsNull_WhenClientIsMocked()
    {
        // Arrange — Moq creates a proxy; the backing field won't exist
        CodeTransparencyClient mockClient = Mock.Of<CodeTransparencyClient>();

        // Act
        MstTransparencyService service = new(mockClient);

        // Assert
        Assert.That(service.ServiceEndpoint, Is.Null);
    }

    /// <summary>
    /// Verifies that ServiceEndpoint works with the two-arg endpoint constructor.
    /// </summary>
    [Test]
    public void ServiceEndpoint_WorksWithEndpointConstructor()
    {
        // Arrange
        Uri endpoint = new("https://staging.cts.azure.com");
        CodeTransparencyClient client = new(endpoint);

        // Act
        MstTransparencyService service = new(client, endpoint);

        // Assert
        Assert.That(service.ServiceEndpoint, Is.EqualTo(endpoint));
    }

    /// <summary>
    /// Verifies that ServiceEndpoint is auto-derived in the full constructor when serviceEndpoint is null.
    /// </summary>
    [Test]
    public void ServiceEndpoint_AutoDerived_InFullConstructor()
    {
        // Arrange
        Uri endpoint = new("https://full-ctor.cts.azure.com");
        CodeTransparencyClient client = new(endpoint);

        // Act
        MstTransparencyService service = new(
            client, null, null, null, null, null, null, null);

        // Assert
        Assert.That(service.ServiceEndpoint, Is.EqualTo(endpoint));
    }

    #endregion

    #region Helpers

    private CoseSign1Message CreateMockCoseSign1Message()
    {
        byte[] testPayload = Encoding.ASCII.GetBytes("Payload1!");
        return messageFactory!.CreateCoseSign1Message(testPayload, signingKeyProvider!, embedPayload: false);
    }

    /// <summary>
    /// Creates a client mock whose CreateEntryAsync commits successfully and whose
    /// GetEntryStatementAsync returns the message with a receipt attached.
    /// </summary>
    private Mock<CodeTransparencyClient> CreateSuccessfulClient(out CoseSign1Message message)
    {
        message = CreateMockCoseSign1Message();
        message.AddReceipts(new List<byte[]> { new byte[] { 1, 2, 3 } });
        BinaryData mockEntryStatement = BinaryData.FromBytes(message.Encode());

        Mock<CodeTransparencyClient> mockClient = new();
        mockClient
            .Setup(c => c.CreateEntryAsync(It.IsAny<BinaryData>(), It.IsAny<bool?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(MstCreateEntryResponses.Committed("2.15"));
        mockClient
            .Setup(c => c.GetEntryStatementAsync("2.15", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(mockEntryStatement, Mock.Of<Response>()));
        return mockClient;
    }

    #endregion
}
