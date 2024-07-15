// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Extensions;

using System.Runtime.InteropServices;

/// <summary>
/// A class that defines extension methods for the <see cref="Stream"/> class.
/// </summary>
public static class StreamExtensions
{
    /// <summary>
    /// Checks if the current <see cref="Stream"/> is null or empty.
    /// </summary>
    /// <param name="stream">The stream to check.</param>
    /// <returns>True if the stream is null or empty; false otherwise.</returns>
    public static bool IsNullOrEmpty(this Stream? stream)
    {
        if (stream == null)
        {
            return true;
        }

        Task<bool> result = Task.Run(() => HasContent(stream));

        return !result.Result;
    }


    private static async Task<bool> HasContent(Stream stream)
    {
        if (stream.CanSeek)
        {
            byte[] buffer = new byte[8];

            // If the stream is STDIN, it will otherwise wait indefinitely for input, so we need a timeout task.
            Task timeout = Task.Delay(TimeSpan.FromMilliseconds(100));
            Task<int> readStdin = stream.ReadAsync(buffer, 0, 8);

            // Go for 100 ms or until we read 8 bytes or reach end of stream, whichever happen first.
            Task finishedFirst = await Task.WhenAny(timeout, readStdin).ConfigureAwait(false);

            await stream.FlushAsync();

            if (finishedFirst == timeout || readStdin.Result == 0)
            {
                // Timeout means there's probably nothing on STDIN. Result == 0 means end of stream. Either way, we're done.
                return false;
            }

            // Reset pointer to the beginning of the stream and return.
            _ = stream.Seek(0, SeekOrigin.Begin);
            return true;
        }

        try
        {
            // Stream is not able to seek so we cannot check if it has content, just ensure the stream length is > 0.
            // In some cases non-seekable streams can return an exception when accessing content related fields because
            // the data can only be read or written as it arrives or is processed sequentially. 
            return stream.Length > 0;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Gets the content of the current <seealso cref="Stream"/>, up to a limit of max array size.
    /// </summary>
    /// <param name="stream">The stream to read.</param>
    /// <returns>The content of the stream as a byte array.</returns>
    /// <exception cref="IOException">The stream was too large to fit into a byte array.</exception>
    /// <exception cref="NotSupportedException">The stream was unreadable.</exception>
    public static byte[] GetBytes(this Stream stream)
    {
        if (stream is MemoryStream ms)
        {
            // MemoryStream already has a backing array so just use that to save compute time.
            return ms.ToArray();
        }

        // It's not a MemoryStream, so copy it to one.
        using MemoryStream msNew = new();
        stream.CopyTo(msNew);
        return msNew.ToArray();
    }

    /// <summary>
    /// Forces a FileStream to unlock all file handles and other resources without waiting for garbage collection.
    /// For other types of streams, it just disposes them.
    /// </summary>
    /// <param name="stream">The stream to dispose.</param>
    /// <param name="sourceFile">The file that the stream reads from and/or writes to, if any.</param>
    public static void HardDispose(this Stream? stream, FileInfo? sourceFile = null)
    {
        sourceFile?.Refresh();  // Update the in-memory file info to reflect the current state of the file on disk.
        if (stream is FileStream fs)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                stream.Close();
                stream.Dispose();
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
            else
            {
                try
                {
                    if (fs.CanRead || fs.CanWrite)  // If the file is not already closed, unlock it.
                    {
                        if (Environment.OSVersion.Platform == PlatformID.MacOSX)
                        {
                            // MacOS doesn't support the Unlock command so we have to use chflags
                            Process p = Process.Start("chflags", $"nouchg {fs.Name}");
                            p.WaitForExit();
                        }
                        else
                        {
                            fs.Unlock(0, fs.Length);
                        }
                    }
                }
                catch (IOException) { } // This just means it's already unlocked, which is fine.
                try
                {
                    stream.Close();
                    stream.Dispose();
                }
                catch (ObjectDisposedException) { } // This just means it's already disposed, which is fine.
            }
        }
        else
        {
            stream?.Dispose();
        }
    }
}
