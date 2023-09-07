// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common;

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
}