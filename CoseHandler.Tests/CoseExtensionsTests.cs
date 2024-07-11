// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

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
    public void FileLoadPartialWriteShort()
    {
        // Arrange
        string text = "This is some text being written slowly."; // 39 chars
        string outPath1 = Path.GetTempFileName();
        string outPath2 = Path.GetTempFileName();
        FileInfo f1 = new(outPath1);
        FileInfo f2 = new(outPath2);

        // Act
        // Start the file writes then start the loading tasks before the writes complete.
        // Both tasks should wait for the writes to complete before loading the content.
        Task t1 = Task.Run(() => WriteTextFileSlowly(outPath1, text));
        byte[] bytes = f1.GetBytesResilient();
        bytes.Length.Should().BeGreaterThan(38);

        var t2 = Task.Run(() => WriteTextFileSlowly(outPath2, text));
        var stream = f2.GetStreamResilient();
        stream!.Length.Should().BeGreaterThan(38);
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
        var writeTask1 = Task.Run(() => WriteTextFileWithDelay(outPath, text, 10));
        try
        {
            _ = await getBytesTask;
        }
        catch (Exception ex)
        {
            // Assert
            ex.Should().BeOfType<IOException>("The file was still empty.");
        }
    }

    private static async Task WriteTextFileSlowly(string path, string text)
    {
        using StreamWriter writer = new(path);
        foreach (char c in text)
        {
            await writer.WriteAsync(c);
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
}