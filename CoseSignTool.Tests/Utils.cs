// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

internal static class Utils
{
    private static readonly byte[] Payload1Bytes = Encoding.ASCII.GetBytes("Payload1!");

    internal static string GetPayloadFile()
    {
        string payloadFile = Path.GetTempFileName();
        File.WriteAllBytes(payloadFile, Payload1Bytes);
        return payloadFile;
    }
}
