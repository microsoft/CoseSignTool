// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

public static class FileInfoExtensions
{
    /// <summary>
    /// Loads the content of a file into a byte array after making sure the file exists, is not empty, and is not locked by another process.
    /// </summary>
    /// <param name="f">The file to read from.</param>
    /// <param name="writeTo">The output target to write status messages to. Default is STDOUT.</param>
    /// <param name="maxWaitTime">The maximum number of seconds to wait for file availability. This value is used up to four times.</param>
    /// <returns>The file content.</returns>
    public static byte[] GetBytesResilient(this FileInfo f, OutputTarget? writeTo = null, int maxWaitTime = 5) => GetBytesOrStream(f, false, writeTo, maxWaitTime).Item1!;

    /// <summary>
    /// Loads the content of a file into a <see cref="FileStream"/> with retries to make sure the file loads successfully and is not empty.
    /// </summary>
    /// <param name="f">The file to read.</param>
    /// <param name="writeTo">The output target to write status messages to. Default is STDOUT.</param>
    /// <param name="maxWaitTime">The maximum number of seconds to wait for file availability. This value is used up to four times.</param>
    /// <returns>The file content.</returns>
    public static FileStream? GetStreamBasic(this FileInfo f, int maxWaitTime = 30, OutputTarget? writeTo = null)
    {
        Exception? ex = null;
        DateTime startTime = DateTime.Now;
        int counter = 0;
        writeTo ??= OutputTarget.StdOut;
        while (SecondsSince(startTime) < 30)
        {
            try
            {
                if (!f.Exists) { throw new FileNotFoundException(); }
                else if (f.Length == 0) { throw new EmptyFileException(f.FullName); }
                return f.OpenRead();
            }
            catch (Exception e)
            {
                if (counter % 4 == 0) { writeTo.Write("."); }
                ex = e;
                Thread.Sleep(250);
                counter++;
            }
        }

        throw ex!;
    }


    /// <summary>
    /// Loads the content of a file into a <see cref="FileStream"/> after making sure the file exists, is not empty, and is not locked by another process.
    /// </summary>
    /// <param name="f">The file to read.</param>
    /// <param name="writeTo">The output target to write status messages to. Default is STDOUT.</param>
    /// <param name="maxWaitTime">The maximum number of seconds to wait for file availability. This value is used up to four times.</param>
    /// <returns>The file content.</returns>
    public static FileStream? GetStreamResilient(this FileInfo f, int maxWaitTime = 5, OutputTarget? writeTo = null) => GetBytesOrStream(f, true, writeTo, maxWaitTime).Item2;

    private static (byte[]?, FileStream?) GetBytesOrStream(FileInfo f, bool isStream, OutputTarget? writer, int maxWaitTime)
    {
        // Make sure the file exists, allowing retries in case it hasn't hit the disk yet.
        DateTime startTime = DateTime.Now;
        while (f is null || !f.Exists)
        {
            Thread.Sleep(100);
            if (OutOfTime(startTime, maxWaitTime))
            {
                throw new FileNotFoundException($"File not found after {SecondsSince(startTime)} seconds.", f?.FullName);
            }
        }

        // Make sure the file is not empty before trying to read it.
        // This check catches the point in time after a file is first created but before it is locked for writing.
        startTime = DateTime.Now;
        while (f.Length == 0)
        {
            Thread.Sleep(100);
            f.Refresh();

            if (OutOfTime(startTime, maxWaitTime))
            {
                throw new EmptyFileException(f.FullName, $"File is empty after {SecondsSince(startTime)} seconds.");
            }
        }

        // Make sure the file isn't locked by another process trying to write to it.
        startTime = DateTime.Now;
        writer ??= OutputTarget.StdErr;
        bool waitMessageStarted = false;
        byte ticks = 0;
        while (IsFileLocked(f))
        {
            long lastLength = f.Length;
            Thread.Sleep(250);
            if (OutOfTime(startTime, maxWaitTime) && lastLength == f.Length)
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
                    throw new IOException($"The file '{f.FullName}' is still locked by another process after {SecondsSince(startTime)} seconds.");
                }
            }
        }

        startTime = DateTime.Now;
        Exception? ex = null;
        while (!OutOfTime(startTime, maxWaitTime))
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

    /// <summary>
    /// Writes a byte array to a file, flushing periodically to clear the buffer.
    /// </summary>
    /// <param name="targetFile">The file to write to.</param>
    /// <param name="bytes">The content to write.</param>
    /// <param name="bufferSize">The number of bytes to write in each batch before clearing the buffer and writing more.</param>
    public static void WriteAllBytesResilient(this FileInfo targetFile, byte[] bytes, int bufferSize = 4096)
        => Task.Run(async () => await targetFile.WriteAllBytesResilientAsync(bytes, bufferSize));

    /// <summary>
    /// Writes a byte array to a file, flushing periodically to clear the buffer.
    /// </summary>
    /// <param name="targetFile">The file to write to.</param>
    /// <param name="bytes">The content to write.</param>
    /// <param name="bufferSize">The number of bytes to write in each batch before clearing the buffer and writing more.</param>
    /// <returns>A Task representing the write operation.</returns>
    public static async Task WriteAllBytesResilientAsync(this FileInfo targetFile, byte[] bytes, int bufferSize = 4096)
        => await WriteAllBytesDelayedAsync(targetFile, bytes, bufferSize, 0);

    /// <summary>
    /// Writes a byte array to a file, flushing periodically to clear the buffer after a time delay. For test use only.
    /// </summary>
    /// <param name="targetFile">The file to write to.</param>
    /// <param name="bytes">The content to write.</param>
    /// <param name="bufferSize">The number of bytes to write in each batch before clearing the buffer and writing more.</param>
    /// <param name="delay">The number of milliseconds to wait before writing the next batch of bytes.</param>
    /// <returns>A Task representing the write operation.</returns>
    public static async Task WriteAllBytesDelayedAsync(this FileInfo targetFile, byte[] bytes, int bufferSize, int delay)
    {
        using FileStream fs = targetFile.OpenWrite();

        for (int offset = 0; offset < bytes.Length; offset += bufferSize)
        {
            int remainingBytes = bytes.Length - offset;
            int bytesToWrite = Math.Min(bufferSize, remainingBytes);

            if (delay > 0)
            {
                Task.Delay(delay).Wait();
            }

            await fs.WriteAsync(bytes, offset, bytesToWrite);
            fs.Flush();
        }

        fs.HardDispose();
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

    private static double SecondsSince(DateTime startTime)
        => Math.Round((DateTime.Now - startTime).TotalSeconds, 2);
}
