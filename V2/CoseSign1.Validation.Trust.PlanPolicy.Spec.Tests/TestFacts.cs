// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Public test fact types used throughout the spec test suite. Each fact type is registered in
/// <see cref="TestFactRegistry"/> with a stable id so the spec compiler can resolve it.
/// </summary>
public sealed class TestMessageFact : IMessageFact
{
    public TestMessageFact(string contentType, int payloadSize, bool detached)
    {
        ContentType = contentType;
        PayloadSize = payloadSize;
        Detached = detached;
    }

    public TrustFactScope Scope => TrustFactScope.Message;

    public string ContentType { get; }

    public int PayloadSize { get; }

    public bool Detached { get; }
}

/// <summary>Public test fact for primary-signing-key scope.</summary>
public sealed class TestSigningKeyFact : ISigningKeyFact
{
    public TestSigningKeyFact(bool isTrusted, string subject)
    {
        IsTrusted = isTrusted;
        Subject = subject;
    }

    public TrustFactScope Scope => TrustFactScope.SigningKey;

    public bool IsTrusted { get; }

    public string Subject { get; }
}

/// <summary>Public test fact for counter-signature scope.</summary>
public sealed class TestCounterSignatureFact : ICounterSignatureFact
{
    public TestCounterSignatureFact(bool present, string host)
    {
        Present = present;
        Host = host;
    }

    public TrustFactScope Scope => TrustFactScope.CounterSignature;

    public bool Present { get; }

    public string Host { get; }
}
