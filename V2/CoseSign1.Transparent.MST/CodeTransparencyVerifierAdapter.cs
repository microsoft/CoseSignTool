// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;

namespace CoseSign1.Transparent.MST;

/// <summary>
/// Default implementation of <see cref="ICodeTransparencyVerifier"/> that delegates to the
/// static <see cref="CodeTransparencyClient.VerifyTransparentStatement"/> method.
/// </summary>
/// <remarks>
/// This adapter exists to enable unit testing of code that depends on MST verification.
/// The underlying <see cref="CodeTransparencyClient.VerifyTransparentStatement"/> is a static method
/// that cannot be mocked directly. By injecting this adapter, consumers can substitute a mock
/// implementation for testing purposes.
/// </remarks>
public class CodeTransparencyVerifierAdapter : ICodeTransparencyVerifier
{
    /// <summary>
    /// Gets the default singleton instance of the adapter.
    /// </summary>
    public static ICodeTransparencyVerifier Default { get; } = new CodeTransparencyVerifierAdapter();

    /// <inheritdoc />
    public void VerifyTransparentStatement(
        byte[] transparentStatementBytes,
        CodeTransparencyVerificationOptions? verificationOptions = null,
        CodeTransparencyClientOptions? clientOptions = null)
    {
        CodeTransparencyClient.VerifyTransparentStatement(
            transparentStatementBytes,
            verificationOptions,
            clientOptions);
    }
}
