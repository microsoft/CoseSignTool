// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

using System;
using System.IO;
using System.Threading;
using CoseSign1;

public static class FileInfoExtensions
{
    /// <summary>
    /// Loads the content of a file into a byte array after making sure the file exists, is not empty, and is not locked by another process.
    /// </summary>
    /// <param name="f">The file to read from.</param>
    /// <param name="writeTo">The output target to write status messages to. Default is STDOUT.</param>
    /// <returns>The file content.</returns>
    public static byte[] GetBytesResilient(this FileInfo f, OutputTarget? writeTo = null) => GetBytesOrStream(f, false, writeTo).Item1!;

    /// <summary>
    /// Loads the content of a file into a <see cref="FileStream"/> after making sure the file exists, is not empty, and is not locked by another process.
    /// </summary>
    /// <param name="f">The file to read.</param>
    /// <param name="writeTo">The output target to write status messages to. Default is STDOUT.</param>
    /// <returns>The file content.</returns>
    public static FileStream? GetStreamResilient(this FileInfo f, OutputTarget? writeTo = null) => GetBytesOrStream(f, true, writeTo).Item2;

    private static (byte[]?, FileStream?) GetBytesOrStream(FileInfo f, bool isStream, OutputTarget? writer)
    {
        // Make sure the file exists, allowing retries in case it hasn't hit the disk yet.
        DateTime startTime = DateTime.Now;
        while (f is null || !f.Exists)
        {
            Thread.Sleep(100);
            if (OutOfTime(startTime, 5))
            {
                throw new FileNotFoundException();
            }
        }

        // Make sure the file is not empty before trying to read it.
        // This check catches the point in time after a file is first created but before it is locked for writing.
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
        writer ??= OutputTarget.StdOut;
        bool waitMessageStarted = false;
        byte ticks = 0;
        while (IsFileLocked(f))
        {
            long lastLength = f.Length;
            Thread.Sleep(250);
            if (OutOfTime(startTime, 5) && lastLength == f.Length)
            {
                if (f.Length > lastLength)
                {
                    ticks++;
                    if (!waitMessageStarted)
                    {
                        waitMessageStarted = true;
                        writer.WriteLine($"Waiting for write of file '{f.FullName}' to complete.");
                    }
                    else if (ticks % 4 == 0)
                    {
                        writer.Write(".");
                    }
                }
                else
                {
                    throw new IOException($"The file '{f.FullName}' is locked by another process.");
                }
            }
        }

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
            catch (IOException e)
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
