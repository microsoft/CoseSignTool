// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Resolution;

using System;
using System.Collections.Generic;
using System.Text.Json;

/// <summary>
/// Represents a DID Document according to W3C DID Core specification.
/// </summary>
public sealed class DidDocument
{
    /// <summary>
    /// Gets the @context URL.
    /// </summary>
    public string Context { get; }

    /// <summary>
    /// Gets the DID identifier.
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets the verification methods.
    /// </summary>
    public IReadOnlyList<VerificationMethod> VerificationMethods { get; }

    /// <summary>
    /// Gets the assertion method references.
    /// </summary>
    public IReadOnlyList<string>? AssertionMethod { get; }

    /// <summary>
    /// Gets the key agreement references.
    /// </summary>
    public IReadOnlyList<string>? KeyAgreement { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DidDocument"/> class.
    /// </summary>
    /// <param name="id">The DID identifier.</param>
    /// <param name="verificationMethods">The verification methods.</param>
    /// <param name="assertionMethod">The assertion method references.</param>
    /// <param name="keyAgreement">The key agreement references.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="id"/> or <paramref name="verificationMethods"/> is <see langword="null"/>.</exception>
    public DidDocument(
        string id,
        IReadOnlyList<VerificationMethod> verificationMethods,
        IReadOnlyList<string>? assertionMethod = null,
        IReadOnlyList<string>? keyAgreement = null)
    {
        Context = DidX509Constants.DidContextUrl;
        Id = id ?? throw new ArgumentNullException(nameof(id));
        VerificationMethods = verificationMethods ?? throw new ArgumentNullException(nameof(verificationMethods));
        AssertionMethod = assertionMethod;
        KeyAgreement = keyAgreement;
    }

    /// <summary>
    /// Converts the DID document to JSON.
    /// </summary>
    /// <param name="indented">Whether to write indented JSON.</param>
    /// <returns>The JSON representation of the document.</returns>
    public string ToJson(bool indented = true)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = indented,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        var doc = new Dictionary<string, object>
        {
            [DidX509Constants.JsonKeyContext] = Context,
            [DidX509Constants.JsonKeyId] = Id,
            [DidX509Constants.JsonKeyVerificationMethod] = VerificationMethods
        };

        if (AssertionMethod != null && AssertionMethod.Count > 0)
        {
            doc[DidX509Constants.JsonKeyAssertionMethod] = AssertionMethod;
        }

        if (KeyAgreement != null && KeyAgreement.Count > 0)
        {
            doc[DidX509Constants.JsonKeyKeyAgreement] = KeyAgreement;
        }

        return JsonSerializer.Serialize(doc, options);
    }
}

/// <summary>
/// Represents a verification method in a DID Document.
/// </summary>
public sealed class VerificationMethod
{
    /// <summary>
    /// Gets the verification method ID.
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets the verification method type.
    /// </summary>
    public string Type { get; }

    /// <summary>
    /// Gets the controller DID.
    /// </summary>
    public string Controller { get; }

    /// <summary>
    /// Gets the public key in JWK format.
    /// </summary>
    public Dictionary<string, object> PublicKeyJwk { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="VerificationMethod"/> class.
    /// </summary>
    /// <param name="id">The verification method ID.</param>
    /// <param name="type">The verification method type.</param>
    /// <param name="controller">The controller DID.</param>
    /// <param name="publicKeyJwk">The public key in JWK format.</param>
    /// <exception cref="ArgumentNullException">Thrown when any required argument is <see langword="null"/>.</exception>
    public VerificationMethod(string id, string type, string controller, Dictionary<string, object> publicKeyJwk)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Type = type ?? throw new ArgumentNullException(nameof(type));
        Controller = controller ?? throw new ArgumentNullException(nameof(controller));
        PublicKeyJwk = publicKeyJwk ?? throw new ArgumentNullException(nameof(publicKeyJwk));
    }
}