// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;
internal class EmptyFileException : IOException
{
    /// <summary>
    /// Initializes an instance of the <see cref="EmptyFileException"/> class for the specified file.
    /// </summary>
    /// <param name="fileName">The file name.</param>
    /// <param name="message">The error text.</param>
    public EmptyFileException(string fileName) : base($"The file at {fileName} was empty or still being written.") { }

    /// <summary>
    /// Initializes an instance of the <see cref="EmptyFileException"/> class for the specified file and adds an error message.
    /// </summary>
    /// <param name="fileName">The file name.</param>
    /// <param name="message">The error text.</param>
    public EmptyFileException(string fileName, string message) : base($"{message}: {fileName}") { }
}
