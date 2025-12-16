// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using System.Text;
using System.Text.Json;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;

namespace CoseSignTool.Tests.Commands.Handlers;

[TestFixture]
public sealed class LiquidDetachedVerificationTests
{
    private sealed record LiquidDetachedTestData(
        string VerifiableObjectBytes,
        string DetachedDocument);

    [Test]
    public void DecodeSign1_LiquidDetached_AlgHeaderIsMinus37_PS256()
    {
        var (signatureBytes, _) = LoadLiquidDetached();

        var message = CoseSign1Message.DecodeSign1(signatureBytes);
        Assert.That(message.Content == null || message.Content.Value.Length == 0, Is.True, "Expected detached payload (null or empty)");
        Assert.That(message.ProtectedHeaders.ContainsKey(CoseHeaderLabel.Algorithm), Is.True);

        var algHeader = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        var reader = new CborReader(algHeader.EncodedValue);

        Assert.That(reader.PeekState(), Is.EqualTo(CborReaderState.NegativeInteger));
        var algId = reader.ReadInt32();
        Assert.That(algId, Is.EqualTo(-37));
    }

    [Test]
    public async Task VerifyCommandHandler_LiquidDetached_RawBytes_ReproducesUnknownAlgorithmError()
    {
        var (signatureBytes, payloadBytes) = LoadLiquidDetached();

        var signaturePath = Path.Combine(Path.GetTempPath(), $"liquid_detached_{Guid.NewGuid():N}.cose");
        var payloadPath = Path.Combine(Path.GetTempPath(), $"liquid_detached_{Guid.NewGuid():N}.json");

        try
        {
            await File.WriteAllBytesAsync(signaturePath, signatureBytes);
            await File.WriteAllBytesAsync(payloadPath, payloadBytes);

            var stringWriter = new StringWriter();
            var formatter = new TextOutputFormatter(stringWriter, stringWriter);
            var handler = new VerifyCommandHandler(formatter);

            var context = CreateInvocationContext(new FileInfo(signaturePath));
            var exitCode = await handler.HandleAsync(context, payloadFile: new FileInfo(payloadPath), signatureOnly: false);
            formatter.Flush();

            var output = stringWriter.ToString();

            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success), $"Unexpected exit code {exitCode}. Output:\n{output}");
            Assert.That(output, Does.Contain("Signature verified successfully"));
        }
        finally
        {
            if (File.Exists(signaturePath))
            {
                File.Delete(signaturePath);
            }

            if (File.Exists(payloadPath))
            {
                File.Delete(payloadPath);
            }
        }
    }

    [Test]
    public async Task VerifyCommandHandler_LiquidDetached_Base64TextFile_FailsToDecode()
    {
        // This matches a common user mistake: saving the Base64 string into a .cose file instead of raw COSE bytes.
        var (signatureBytes, payloadBytes) = LoadLiquidDetached();
        var base64Signature = Convert.ToBase64String(signatureBytes);

        var signaturePath = Path.Combine(Path.GetTempPath(), $"liquid_detached_{Guid.NewGuid():N}.cose");
        var payloadPath = Path.Combine(Path.GetTempPath(), $"liquid_detached_{Guid.NewGuid():N}.json");

        try
        {
            await File.WriteAllTextAsync(signaturePath, base64Signature, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            await File.WriteAllBytesAsync(payloadPath, payloadBytes);

            var stringWriter = new StringWriter();
            var formatter = new TextOutputFormatter(stringWriter, stringWriter);
            var handler = new VerifyCommandHandler(formatter);

            var context = CreateInvocationContext(new FileInfo(signaturePath));
            var exitCode = await handler.HandleAsync(context, payloadFile: new FileInfo(payloadPath), signatureOnly: false);
            formatter.Flush();

            var output = stringWriter.ToString();

            Assert.That(exitCode, Is.EqualTo((int)ExitCode.InvalidSignature));
            Assert.That(output, Does.Contain("Failed to decode COSE Sign1 message"), $"Output:\n{output}");
            Assert.That(output, Does.Contain("Base64").And.Contain("Decode"), $"Output:\n{output}");
        }
        finally
        {
            if (File.Exists(signaturePath))
            {
                File.Delete(signaturePath);
            }

            if (File.Exists(payloadPath))
            {
                File.Delete(payloadPath);
            }
        }
    }

    private static InvocationContext CreateInvocationContext(FileInfo signature)
    {
        var command = new Command("verify");
        var signatureArg = new Argument<string?>("signature");
        command.AddArgument(signatureArg);

        var parseResult = command.Parse($"verify \"{signature.FullName}\"");
        return new InvocationContext(parseResult);
    }

    private static (byte[] SignatureBytes, byte[] PayloadBytes) LoadLiquidDetached()
    {
        var testDataPath = Path.Combine(AppContext.BaseDirectory, "TestData", "liquid_detached.json");
        Assert.That(File.Exists(testDataPath), Is.True, $"Test data not found at {testDataPath}");

        var json = File.ReadAllText(testDataPath);
        var data = JsonSerializer.Deserialize<LiquidDetachedTestData>(json);
        Assert.That(data, Is.Not.Null);
        Assert.That(data!.VerifiableObjectBytes, Is.Not.Empty);
        Assert.That(data.DetachedDocument, Is.Not.Empty);

        // This is the same decoding the user tried in PowerShell: [Convert]::FromBase64String(...)
        var signatureBytes = Convert.FromBase64String(data.VerifiableObjectBytes);

        // DetachedDocument is Base64-encoded payload bytes.
        var payloadBytes = Convert.FromBase64String(data.DetachedDocument);
        return (signatureBytes, payloadBytes);
    }
}
