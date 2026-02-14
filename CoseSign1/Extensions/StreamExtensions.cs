// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Extensions;

/// <summary>
/// A class that defines extension methods for the <see cref="Stream"/> class.
/// </summary>
public static class StreamExtensions
{
    /// <summary>
    /// Checks if the current <see cref="Stream"/> is null or empty.
    /// </summary>
    /// <param name="stream">The stream to check.</param>
    /// <param name="maxWait">The number of milliseconds before timeout. Default is 100.</param>
    /// <returns>True if the stream is null or empty; false otherwise.</returns>
    public static bool IsNullOrEmpty(this Stream? stream, int maxWait = 100)
    {
        if (stream == null)
        {
            return true;
        }

        Task<bool> result = Task.Run(() => HasContent(stream, maxWait));

        return !result.Result;
    }


    private static async Task<bool> HasContent(Stream stream, int maxWait = 100)
    {
        if (stream.CanSeek)
        {
            byte[] buffer = new byte[8];

            // If the stream is STDIN, it will otherwise wait indefinitely for input, so we need a timeout task.
            Task timeout = Task.Delay(TimeSpan.FromMilliseconds(maxWait));
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

        // Stream is not seekable (e.g., piped stdin on Linux/macOS).
        // We cannot peek without consuming data, so we need to handle this differently.
        try
        {
            // First try to check the Length property if available.
            return stream.Length > 0;
        }
        catch (NotSupportedException)
        {
            // Length is not supported (common for piped streams).
            // For non-seekable streams where we can't check length, we assume there IS content
            // if the stream is readable. The actual read operation will fail gracefully if empty.
            // This fixes piping on Linux/macOS where stdin.Length throws NotSupportedException.
            return stream.CanRead;
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
                        fs.Unlock(0, fs.Length);    // Note: This doesn't do anything in MacOS.
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
