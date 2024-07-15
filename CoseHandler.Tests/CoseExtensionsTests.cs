// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

using System.Numerics;

[TestClass]
public class CoseExtensionsTests
{
    private readonly byte[] Payload1 = Encoding.ASCII.GetBytes("Payload1!");
    private const string SubjectName1 = $"{nameof(CoseExtensionsTests)}_TestCert";
    private static readonly X509Certificate2Collection CertChain = TestCertificateUtils.CreateTestChain(SubjectName1);
    private static readonly X509Certificate2 SelfSignedRoot = CertChain[0];
    private static readonly X509Certificate2 ChainedCert = CertChain[^1];

    [TestMethod]
    public void TryGetSigningCert()
    {
        // Create a COSE signature from a chained cert
        string signedFile = Path.GetTempFileName();
        X509Certificate2CoseSigningKeyProvider signer = new (ChainedCert);
        ReadOnlyMemory<byte> sigBlock = CoseHandler.Sign(Payload1, signer, false, new FileInfo(signedFile));

        // Make sure we can read it
        byte[] bytesFromMemory = sigBlock.ToArray();
        CoseSign1Message msg = CoseMessage.DecodeSign1(bytesFromMemory);
        msg.Should().NotBeNull();

        // Read it from the output file we created
        byte[] bytesFromFile = File.ReadAllBytes(signedFile);

        // The byte arrays should match and be readable as COSE messages
        bytesFromFile.Should().Equal(bytesFromMemory);
        msg = CoseMessage.DecodeSign1(bytesFromMemory);

        CoseSign1MessageExtensions.TryGetSigningCertificate(msg, out X509Certificate2? signCert).Should().BeTrue();
        signCert.Should().NotBeNull();
        signCert?.Thumbprint.Should().Be(ChainedCert.Thumbprint);
    }

    [TestMethod]
    public void FileLoadPartialWriteBytes()
    {
        SkipIfMac();

        // Arrange
        string text = "This is some text being written slowly."; // 39 chars
        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        string outPath = Path.GetTempFileName();
        FileInfo f = new(outPath);

        // Act
        // Start the file write then start the loading task before the write completes.
        //_ = Task.Run(() => WriteTextFileSlowly(outPath, text));
        _ = Task.Run(() => f.WriteAllBytesDelayedAsync(textBytes, 1, 100));
        byte[] bytes = f.GetBytesResilient();

        // Assert
        bytes.Length.Should().BeGreaterThan(38, "GetBytesResilient should keep reading until the write is complete.");
    }

    [TestMethod]
    public void FileLoadPartialWriteStream()
    {
        // Arrange
        string text = "This is some text being written slowly."; // 39 chars
        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        string outPath = Path.GetTempFileName();
        FileInfo f = new(outPath);

        // Act
        // Start the file write then start the loading task before the write completes.
        //_ = Task.Run(() => WriteTextFileSlowly(outPath, text));
        _ = Task.Run(() => f.WriteAllBytesDelayedAsync(textBytes, 1, 100));
        var stream = f.GetStreamResilient();

        // Assert
        stream!.Length.Should().BeGreaterThan(38, "GetStreamResilient should keep reading until the write is complete.");
    }

    [TestMethod]
    public async Task FileLoadEmptyFileDelayWrite()
    {
        // Arrange
        string text = "This is some text that will be written to a file eventually.";
        string outPath = Path.GetTempFileName();
        FileInfo f = new(outPath);
        var getBytesTask = Task.Run(() => f.GetBytesResilient(writeTo: OutputTarget.StdOut));

        // Act
        // Start the file write. The loading task should time out before the first character is written.
        _ = Task.Run(() => WriteTextFileWithDelay(outPath, text, 10));
        try
        {
            _ = await getBytesTask;

            // Assert
            Assert.Fail("The file should have thrown an IOException because it was still empty.");
        }
        catch (IOException) { }
    }

    private static async Task WriteTextFileSlowly(string path, string text)
    {
        using StreamWriter writer = new(path);
        foreach (char c in text)
        {
            await writer.WriteAsync(c);
            await writer.FlushAsync();
            await Task.Delay(100);
        }
    }

    private static async Task WriteTextFileWithDelay(string path, string text, int secondsToWait)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.None);
        using StreamWriter writer = new(stream);
        Thread.Sleep(secondsToWait * 1000);
        await writer.WriteAsync(text);
    }

    private static void SkipIfMac()
    {
        if (Environment.OSVersion.Platform == PlatformID.MacOSX)
        {
            Assert.Inconclusive("Functionality not supported on MacOS.");
        }
    }
}