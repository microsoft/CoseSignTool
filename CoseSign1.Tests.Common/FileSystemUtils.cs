// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common;

using System.Runtime.CompilerServices;
using System.Text;

public static class FileSystemUtils
{
    /// <summary>
    /// Creates a randomly named temporary file on disk.
    /// </summary>
    /// <returns>The file name.</returns>
    public static string CreateTemporaryFile()
    {
        string fileName;
        try
        {
            fileName = Path.GetTempFileName();
            FileInfo fileInfo = new(fileName) { Attributes = FileAttributes.Temporary };
        }
        catch (IOException e)
        {
            System.Diagnostics.Debugger.Log(0, "", $"Could not create a temp file: {e.Message}");
            throw;
        }

        return fileName;
    }

    /// <summary>
    /// Creates a randomly generated payload file on disk for signature testing.
    /// </summary>
    /// <param name="caller">The name of the calling method (set by default).</param>
    /// <param name="content">The content of the file. By default, the string "Payload1!" is used.</param>
    /// <returns>The path to the new file.</returns>
    public static string GeneratePayloadFile([CallerMemberName] string caller = "", string? content = null)
    {
        string fileName = Path.GetTempFileName().Replace(".tmp", $"-{caller}.spdx.json");
        content ??= "Payload1!";
        byte[] bytes = Encoding.ASCII.GetBytes(content);
        File.WriteAllBytes(fileName, bytes);
        return new(fileName);
    }
}