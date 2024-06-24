// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

using System;
using System.IO;
using System.Threading;

public static class FileInfoExtensions
{
    public static byte[] GetBytesResilient(this FileInfo f) => GetBytesOrStream(f, false).Item1!;

    // Wait up to X seconds if the file does not exist or is 0 - length
    // If Read still fails(and not an access-related exception) check for write in progress by polling every ¼ second or so until 3 consecutive polls return the same file length.
    // That, and maybe make the output messages more granular -file not found vs.file empty vs.file unreadable.

    // This or File.OpenRead is called twice in CoseHandler,
    // once in ValidateCommand to call CoseHandler, once in CoseCommand to read a payload stream from file.
    public static FileStream? GetStreamResilient(this FileInfo f) => GetBytesOrStream(f, true).Item2!;

    private static (byte[]?, FileStream?) GetBytesOrStream(FileInfo f, bool isStream)
    {
        // FileInfo constructor throws if the file doesn't exist, so I don't need to check for that here. Caller should wait for file existence.
        int maxWaitTimeInSeconds = 5;
        DateTime startTime = DateTime.Now;
        Exception? ex;
        while (true)
        {
            if (f is null || f.FullName is null || f.Length == 0)
            {
                Thread.Sleep(100); // Wait for 100 milliseconds before checking again
                continue;
            }

            try
            {
                FileStream? fs = isStream? new(f.FullName, FileMode.Open, FileAccess.Read) : null;    // I could use File.OpenRead here but the FileStream constructor gives more granular exceptions
                // Depending on test results, I may need to also make sure the stream is done being written to before returning it
                byte[]? bytes = isStream ? null : File.ReadAllBytes(f.FullName);
                return (bytes, fs);
            }
            catch (Exception e)     // I should only catch the types of exceptions that might be fixed over time, such as could come from an incomplete file write
            {
                ex = e;
                Thread.Sleep(100); // Wait for 100 milliseconds before checking again
            }

            if ((DateTime.Now - startTime).TotalSeconds >= maxWaitTimeInSeconds)
            {
                break;
            }
        }

        throw ex!;
    }
}
