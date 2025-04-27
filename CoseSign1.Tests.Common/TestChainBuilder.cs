// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common;

using System.Collections.Generic;
using System.Runtime.CompilerServices;
using CoseSign1.Certificates.Interfaces;

/// <summary>
/// Custom Chain Builder Class Created For Integration Tests Purpose
/// </summary>
public class TestChainBuilder : ICertificateChainBuilder, IDisposable
{
    private readonly X509Chain DefaultChainBuilder;

    private readonly string? TestName;

    public TestChainBuilder()
    {
        DefaultChainBuilder = new X509Chain();
    }

    /// <summary>
    /// Added this just for the purpose of tests
    /// </summary>
    /// <param name="testName">his would be used as the testName while creating the test chain in ChainElements()</param>
    public TestChainBuilder([CallerMemberName] string testName = "none")
    {
        DefaultChainBuilder = new X509Chain();
        TestName = testName;
    }

    /// <summary>
    /// overloading this behavior so as to make the integration tests work
    /// </summary>
    public IReadOnlyCollection<X509Certificate2> ChainElements
    {
        get
        {
            X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain(TestName);

            List<X509Certificate2> elements = new(testChain);

            return elements;
        }
    }

    //overloading this so as to ensure there are no dependencies for the integration tests on X509Chain Build() method
    public bool Build(X509Certificate2 certificate)
    {
        return true;
    }

    /// <inheritdoc/>
    public X509ChainPolicy ChainPolicy { get => DefaultChainBuilder.ChainPolicy; set => DefaultChainBuilder.ChainPolicy = value; }

    /// <inheritdoc/>
    public X509ChainStatus[] ChainStatus => DefaultChainBuilder.ChainStatus;

    /// <inheritdoc/>
    public void Dispose()
    {
        DefaultChainBuilder.Dispose();
        GC.SuppressFinalize(this);
    }
}
