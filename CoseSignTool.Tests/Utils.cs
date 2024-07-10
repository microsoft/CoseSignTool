// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

using System.Runtime.CompilerServices;

internal static class Utils
{
    internal static string GeneratePayloadFile([CallerMemberName] string caller = "", string? content = null)
    {
        string fileName = Path.GetTempFileName().Replace(".tmp", $"-{caller}.spdx.json");
        content ??= "Payload1!";
        byte[] bytes = Encoding.ASCII.GetBytes(content);
        File.WriteAllBytes(fileName, bytes);
        return new(fileName);
    }
}
