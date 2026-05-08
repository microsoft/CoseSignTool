// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

/// <summary>
/// Test-only fact registry that maps test fact CLR types to stable ids. Includes the standard
/// V2 fact catalog so that scenarios crossing packs work end-to-end.
/// </summary>
internal static class TestFactRegistry
{
    public const string TestMessage = "test-message/v1";
    public const string TestSigningKey = "test-signing-key/v1";
    public const string TestCounterSignature = "test-counter-signature/v1";

    public static StaticFactRegistry Build()
    {
#pragma warning disable CS0618 // StaticFactRegistry remains the conformance baseline; tests must keep exercising it through Phase 4.
        var defaults = new List<KeyValuePair<string, Type>>(StaticFactRegistry.BuildDefaultMappings())
        {
            new KeyValuePair<string, Type>(TestMessage, typeof(TestMessageFact)),
            new KeyValuePair<string, Type>(TestSigningKey, typeof(TestSigningKeyFact)),
            new KeyValuePair<string, Type>(TestCounterSignature, typeof(TestCounterSignatureFact)),
        };

        return new StaticFactRegistry(defaults);
#pragma warning restore CS0618
    }
}
