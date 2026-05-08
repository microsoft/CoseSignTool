// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

using System;

/// <summary>
/// Thrown when <see cref="Compilation.TrustPolicySpecCompiler.Compile"/> cannot lower a
/// <see cref="TrustPolicySpec"/> to a runtime <see cref="CoseSign1.Validation.Trust.TrustPlanPolicy"/>.
/// </summary>
/// <remarks>
/// The <see cref="Code"/> property carries one of the stable values from
/// <see cref="TrustPolicyDiagnosticCodes"/>. Callers that surface this exception to translator
/// diagnostics should map the code into a translation diagnostic rather than swallow the message.
/// </remarks>
[Serializable]
public sealed class TrustPolicySpecCompilationException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicySpecCompilationException"/> class.
    /// </summary>
    public TrustPolicySpecCompilationException()
        : base()
    {
        Code = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicySpecCompilationException"/> class
    /// with a human-readable message and no diagnostic code.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public TrustPolicySpecCompilationException(string message)
        : base(message)
    {
        Code = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicySpecCompilationException"/> class
    /// with a human-readable message and inner exception, but no diagnostic code.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="inner">The inner exception.</param>
    public TrustPolicySpecCompilationException(string message, Exception inner)
        : base(message, inner)
    {
        Code = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicySpecCompilationException"/> class
    /// with a stable diagnostic code and human-readable message.
    /// </summary>
    /// <param name="code">A stable diagnostic code from <see cref="TrustPolicyDiagnosticCodes"/>.</param>
    /// <param name="message">A human-readable message that names the offending construct.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="code"/> or <paramref name="message"/> is null.</exception>
    public TrustPolicySpecCompilationException(string code, string message)
        : base(message)
    {
        Cose.Abstractions.Guard.ThrowIfNull(code);
        Cose.Abstractions.Guard.ThrowIfNull(message);

        Code = code;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicySpecCompilationException"/> class
    /// with a stable diagnostic code, message, and inner exception.
    /// </summary>
    /// <param name="code">A stable diagnostic code from <see cref="TrustPolicyDiagnosticCodes"/>.</param>
    /// <param name="message">A human-readable message that names the offending construct.</param>
    /// <param name="inner">The underlying exception that caused the compilation failure.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="code"/>, <paramref name="message"/>, or <paramref name="inner"/> is null.</exception>
    public TrustPolicySpecCompilationException(string code, string message, Exception inner)
        : base(message, inner)
    {
        Cose.Abstractions.Guard.ThrowIfNull(code);
        Cose.Abstractions.Guard.ThrowIfNull(message);
        Cose.Abstractions.Guard.ThrowIfNull(inner);

        Code = code;
    }

    /// <summary>
    /// Gets the stable diagnostic code for this compilation failure. Empty string when the
    /// exception was constructed without a code (e.g., via the standard exception constructors).
    /// </summary>
    public string Code { get; }
}
