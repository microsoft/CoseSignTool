// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;

namespace CoseSign1;

/// <summary>
/// Chains multiple <see cref="ICoseHeaderExtender"/> instances and applies them in order to protected and unprotected COSE header maps.
/// </summary>
/// <remarks>
/// This class allows composition of multiple header extenders, executing each in sequence. Each extender's output is passed as input to the next.
/// If any extender returns <c>null</c>, an <see cref="InvalidOperationException"/> is thrown. The input list and all elements must be non-null.
/// </remarks>
public sealed class ChainedCoseHeaderExtender : ICoseHeaderExtender
{
    private readonly IReadOnlyList<ICoseHeaderExtender> Extenders;

    /// <summary>
    /// Initializes a new instance of the <see cref="ChainedCoseHeaderExtender"/> class.
    /// </summary>
    /// <param name="extenders">The sequence of <see cref="ICoseHeaderExtender"/> instances to chain. Must not be null and must not contain null elements.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="extenders"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if any element in <paramref name="extenders"/> is null.</exception>
    public ChainedCoseHeaderExtender(IEnumerable<ICoseHeaderExtender> extenders)
    {
        if (extenders == null)
        {
            throw new ArgumentNullException(nameof(extenders));
        }

        if (extenders.Any(e => e == null))
        {
            throw new ArgumentException("One or more extenders are null.", nameof(extenders));
        }

        Extenders = extenders.ToList().AsReadOnly();
    }

    /// <summary>
    /// Applies all chained extenders to the provided protected headers in order.
    /// </summary>
    /// <param name="protectedHeaders">The initial <see cref="CoseHeaderMap"/> to extend. Must not be null.</param>
    /// <returns>The extended <see cref="CoseHeaderMap"/> after all extenders have been applied.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="protectedHeaders"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown if any extender returns null.</exception>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        if (protectedHeaders == null)
        {
            throw new ArgumentNullException(nameof(protectedHeaders));
        }

        CoseHeaderMap result = protectedHeaders;
        foreach (ICoseHeaderExtender extender in Extenders)
        {
            result = extender.ExtendProtectedHeaders(result);
            if (result == null)
            {
                throw new InvalidOperationException($"Extender {extender.GetType().Name} returned null from ExtendProtectedHeaders.");
            }
        }
        return result;
    }

    /// <summary>
    /// Applies all chained extenders to the provided unprotected headers in order.
    /// </summary>
    /// <param name="unProtectedHeaders">The initial <see cref="CoseHeaderMap"/> to extend. May be null.</param>
    /// <returns>The extended <see cref="CoseHeaderMap"/> after all extenders have been applied.</returns>
    /// <exception cref="InvalidOperationException">Thrown if any extender returns null.</exception>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        CoseHeaderMap? result = unProtectedHeaders;
        foreach (ICoseHeaderExtender extender in Extenders)
        {
            result = extender.ExtendUnProtectedHeaders(result);
            if (result == null)
            {
                throw new InvalidOperationException($"Extender {extender.GetType().Name} returned null from ExtendUnProtectedHeaders.");
            }
        }
        return result!;
    }
}
