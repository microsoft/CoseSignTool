// ---------------------------------------------------------------------------
// <copyright file="X509ChainBuilder.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Certificates.Local;

/// <summary>
/// A default <see cref="ICertificateChainBuilder"/> which wraps <see cref="X509Chain"/>.
/// </summary>
public class X509ChainBuilder : ICertificateChainBuilder, IDisposable
{
    private readonly X509Chain DefaultChainBuilder;

    /// <summary>
    /// Creates a new <see cref="X509ChainBuilder"/> for chain building.
    /// </summary>
    public X509ChainBuilder()
    {
        DefaultChainBuilder = new X509Chain();
    }

    /// <inheritdoc/>
    public virtual IReadOnlyCollection<X509Certificate2> ChainElements
    {
        get
        {
            List<X509Certificate2> elements = new(DefaultChainBuilder.ChainElements.Count);
            foreach (X509ChainElement element in DefaultChainBuilder.ChainElements)
            {
                elements.Add(element.Certificate);
            }

            return elements;
        }
    }

    /// <inheritdoc/>
    public virtual X509ChainPolicy ChainPolicy { get => DefaultChainBuilder.ChainPolicy; set => DefaultChainBuilder.ChainPolicy = value; }

    /// <inheritdoc/>
    public virtual X509ChainStatus[] ChainStatus => DefaultChainBuilder.ChainStatus;

    /// <inheritdoc/>
    public virtual bool Build(X509Certificate2 certificate) => DefaultChainBuilder.Build(certificate);

    /// <inheritdoc/>
    public void Dispose()
    {
        DefaultChainBuilder.Dispose();
        GC.SuppressFinalize(this);
    }
}