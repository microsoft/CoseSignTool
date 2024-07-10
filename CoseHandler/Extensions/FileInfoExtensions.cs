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
    public static FileStream? GetStreamResilient(this FileInfo f) => GetBytesOrStream(f, true).Item2;

    private static (byte[]?, FileStream?) GetBytesOrStream(FileInfo f, bool isStream)
    {
        // FileInfo constructor throws if the file doesn't exist, so I don't need to check for that here. Caller should wait for file existence.

        //// Make sure the file exists, allowing retries in case it hasn't hit the disk yet.
        DateTime startTime = DateTime.Now;
        while (f is null)
        {
            Thread.Sleep(100);
            if (OutOfTime(startTime, 5))
            {
                throw new FileNotFoundException();
            }
        }

        // Make sure the file is not empty before trying to read it.
        // This check is necessary because there is a point where the file exists but is still empty before it is locked for writing.
        startTime = DateTime.Now;
        while (f.Length == 0)
        {
            Thread.Sleep(100);
            f.Refresh();

            if (OutOfTime(startTime, 5))
            {
                throw new IOException("File is empty.");
            }
        }

        // Make sure the file isn't locked by another process trying to write to it.
        startTime = DateTime.Now;
        while (IsFileLocked(f))
        {
            Thread.Sleep(100);
            if (OutOfTime(startTime, 15))
            {
                throw new IOException($"The file '{f.FullName}' is still in use by another process.");
            }
        }

        // File is not empty, but watch the length to make sure it's done being written
        //while (f.Length > lastLength)
        //{
        //    Thread.Sleep(250);
        //    f.Refresh();
        //    lastLength = f.Length;
        //}
        startTime = DateTime.Now;
        Exception? ex = null;
        while (!OutOfTime(startTime, 5))
        {
            // Try loading the file content. If it fails, the exception will be caught and we'll try again.
            try
            {                
                FileStream? fs = isStream ? new(f.FullName, FileMode.Open, FileAccess.Read) : null;
                byte[]? bytes = isStream ? null : File.ReadAllBytes(f.FullName);
                return (bytes, fs);
            }
            catch (IOException e)     // TODO: I should only catch the types of exceptions that might be fixed over time, such as could come from an incomplete file write
            {
                ex = e;
                Thread.Sleep(250); // Wait for 250 milliseconds before checking again
            } 
        }

        throw ex!;
    }

    private static bool IsFileLocked(FileInfo f)
    {
        try
        {
            using FileStream? stream = f.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }

    private static bool OutOfTime(DateTime startTime, int maxWaitTimeInSeconds) =>
        (DateTime.Now - startTime).TotalSeconds >= maxWaitTimeInSeconds;
}
