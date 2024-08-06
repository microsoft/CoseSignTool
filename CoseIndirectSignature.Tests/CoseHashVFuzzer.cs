// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose Fuzzer

namespace CoseIndirectSignature.Tests;

/// <summary>
/// Class used to fuzz the parsing logic for CoseHashV and CborReader under the covers.
/// </summary>
public static class CoseHashVFuzzer
{
    /// <summary>
    /// Fuzz target method matching signatures expected for fuzzing.
    /// </summary>
    /// <param name="input"></param>
    public static void FuzzCoseHashVParser(ReadOnlySpan<byte> input)
    {
        try
        {
            CoseHashV objectUnderTest = CoseHashV.Deserialize(input);
        }
        // deserialize documents two exceptions to be thrown, so catch them as known "good" behavior.
        catch(Exception ex) when (ex is InvalidCoseDataException || ex is ArgumentNullException)
        {
        }
    }
}
