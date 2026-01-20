// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions;
using System.Text.Json;
using System.Linq;

internal static class MstCodeTransparencyOptions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorOfflineJwksNotConfigured = "Offline JWKS was not configured";
        public const string ErrorOfflineTrustNotSupported = "Offline trust configuration is not supported by this Azure.Security.CodeTransparency version.";

        public const string JwksKeysPropertyName = "keys";

        public const string JwkPropertyAlg = "alg";
        public const string JwkPropertyCrv = "crv";
        public const string JwkPropertyD = "d";
        public const string JwkPropertyDp = "dp";
        public const string JwkPropertyDq = "dq";
        public const string JwkPropertyE = "e";
        public const string JwkPropertyK = "k";
        public const string JwkPropertyKid = "kid";
        public const string JwkPropertyKty = "kty";
        public const string JwkPropertyN = "n";
        public const string JwkPropertyP = "p";
        public const string JwkPropertyQ = "q";
        public const string JwkPropertyQi = "qi";
        public const string JwkPropertyUse = "use";
        public const string JwkPropertyX = "x";
        public const string JwkPropertyX5c = "x5c";
        public const string JwkPropertyY = "y";

        public const string PropertyTrustedJwks = "TrustedJwks";
        public const string PropertyTrustedJwksJson = "TrustedJwksJson";
        public const string PropertyTrustedKeys = "TrustedKeys";
        public const string PropertyTrustedKeysJson = "TrustedKeysJson";
        public const string PropertyTrustedSigningKeys = "TrustedSigningKeys";
        public const string PropertyTrustedKeySet = "TrustedKeySet";
        public const string PropertyTrustedKeySetJson = "TrustedKeySetJson";
    }

    internal static CodeTransparencyVerificationOptions CreateVerificationOptions(MstTrustOptions options)
    {
        // IMPORTANT: issuer/ledger identity is a trust decision and should be expressed in the TrustPlan.
        // The MST module configuration can optionally provide an AuthorizedDomains list as a defense-in-depth
        // verification constraint, but we should not silently infer one from the verification endpoint.
        IList<string>? authorizedDomains = options.AuthorizedDomains?.ToList();

        // If no authorized list is provided, do not treat receipts as "unauthorized" and fail.
        // Instead, verify all receipts and let TrustPlanPolicy decide which issuer/ledger identities are trusted.
        var unauthorizedBehavior = (authorizedDomains == null || authorizedDomains.Count == 0)
            ? UnauthorizedReceiptBehavior.VerifyAll
            : UnauthorizedReceiptBehavior.FailIfPresent;

        return new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = authorizedDomains,
            UnauthorizedReceiptBehavior = unauthorizedBehavior,
        };
    }

    internal static void ConfigureOfflineKeys(
        CodeTransparencyVerificationOptions verificationOptions,
        MstTrustOptions options,
        IReadOnlyList<string> issuerHosts)
    {
        Guard.ThrowIfNull(verificationOptions);
        Guard.ThrowIfNull(options);
        Guard.ThrowIfNull(issuerHosts);

        if (!options.OfflineOnly)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(options.OfflineTrustedJwksJson))
        {
            throw new InvalidOperationException(ClassStrings.ErrorOfflineJwksNotConfigured);
        }

        // The pinned payload is a JWKS document: { "keys": [ ... ] }
        // Azure.Security.CodeTransparency.JsonWebKey is not directly deserializable via System.Text.Json,
        // so we parse the JSON and construct the SDK model via its model factory.
        using var doc = JsonDocument.Parse(options.OfflineTrustedJwksJson);
        if (!doc.RootElement.TryGetProperty(ClassStrings.JwksKeysPropertyName, out var keysElement) || keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(ClassStrings.ErrorOfflineJwksNotConfigured);
        }

        var keys = new List<JsonWebKey>();
        foreach (var keyElement in keysElement.EnumerateArray())
        {
            if (keyElement.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var kty = TryGetString(keyElement, ClassStrings.JwkPropertyKty);
            if (string.IsNullOrWhiteSpace(kty))
            {
                continue;
            }

            var x5c = TryGetStringArray(keyElement, ClassStrings.JwkPropertyX5c);

            // Most JWKS fields are optional; pass through what is present.
            var jwk = SecurityCodeTransparencyModelFactory.JsonWebKey(
                alg: TryGetString(keyElement, ClassStrings.JwkPropertyAlg),
                crv: TryGetString(keyElement, ClassStrings.JwkPropertyCrv),
                d: TryGetString(keyElement, ClassStrings.JwkPropertyD),
                dp: TryGetString(keyElement, ClassStrings.JwkPropertyDp),
                dq: TryGetString(keyElement, ClassStrings.JwkPropertyDq),
                e: TryGetString(keyElement, ClassStrings.JwkPropertyE),
                k: TryGetString(keyElement, ClassStrings.JwkPropertyK),
                kid: TryGetString(keyElement, ClassStrings.JwkPropertyKid),
                kty: kty,
                n: TryGetString(keyElement, ClassStrings.JwkPropertyN),
                p: TryGetString(keyElement, ClassStrings.JwkPropertyP),
                q: TryGetString(keyElement, ClassStrings.JwkPropertyQ),
                qi: TryGetString(keyElement, ClassStrings.JwkPropertyQi),
                use: TryGetString(keyElement, ClassStrings.JwkPropertyUse),
                x: TryGetString(keyElement, ClassStrings.JwkPropertyX),
                x5c: x5c,
                y: TryGetString(keyElement, ClassStrings.JwkPropertyY));

            keys.Add(jwk);
        }

        if (keys.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorOfflineJwksNotConfigured);
        }

        // NOTE: this is a single JWKS document; we dynamically map it to issuer host(s) discovered in the message.
        var jwks = SecurityCodeTransparencyModelFactory.JwksDocument(keys);

        var offlineKeys = new CodeTransparencyOfflineKeys();
        foreach (var host in issuerHosts)
        {
            if (!string.IsNullOrWhiteSpace(host))
            {
                offlineKeys.Add(host, jwks);
            }
        }

        // If we couldn't discover hosts, still set an empty store and force no-network behavior.
        verificationOptions.OfflineKeys = offlineKeys;
        verificationOptions.OfflineKeysBehavior = OfflineKeysBehavior.NoFallbackToNetwork;
    }

    private static string? TryGetString(JsonElement obj, string propertyName)
    {
        if (obj.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String)
        {
            return value.GetString();
        }

        return null;
    }

    private static IEnumerable<string> TryGetStringArray(JsonElement obj, string propertyName)
    {
        if (!obj.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        var results = new List<string>();
        foreach (var element in value.EnumerateArray())
        {
            if (element.ValueKind == JsonValueKind.String)
            {
                var s = element.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    results.Add(s);
                }
            }
        }

        return results;
    }

    internal static CodeTransparencyClientOptions? TryCreateClientOptionsForOfflineJwks(MstTrustOptions options)
    {
        if (!options.OfflineOnly)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(options.OfflineTrustedJwksJson))
        {
            throw new InvalidOperationException(ClassStrings.ErrorOfflineJwksNotConfigured);
        }

        var clientOptions = new CodeTransparencyClientOptions();

        // The Azure SDK surface is evolving across preview versions; configure by reflection to avoid hard-binding
        // to a single property name.
        if (TrySetTrustedKeys(clientOptions, options.OfflineTrustedJwksJson))
        {
            return clientOptions;
        }

        throw new NotSupportedException(ClassStrings.ErrorOfflineTrustNotSupported);
    }

    private static bool TrySetTrustedKeys(CodeTransparencyClientOptions options, string jwksJson)
    {
        // Try a small set of likely property names across preview versions.
        var candidates = new[]
        {
            ClassStrings.PropertyTrustedJwksJson,
            ClassStrings.PropertyTrustedKeySetJson,
            ClassStrings.PropertyTrustedKeysJson,
            ClassStrings.PropertyTrustedJwks,
            ClassStrings.PropertyTrustedKeySet,
            ClassStrings.PropertyTrustedSigningKeys,
            ClassStrings.PropertyTrustedKeys,
        };

        var t = options.GetType();
        foreach (var name in candidates)
        {
            var p = t.GetProperty(name, BindingFlags.Instance | BindingFlags.Public);
            if (p == null || !p.CanWrite)
            {
                continue;
            }

            if (p.PropertyType == typeof(string))
            {
                p.SetValue(options, jwksJson);
                return true;
            }

            if (p.PropertyType == typeof(BinaryData))
            {
                p.SetValue(options, BinaryData.FromString(jwksJson));
                return true;
            }

            if (p.PropertyType == typeof(byte[]))
            {
                p.SetValue(options, System.Text.Encoding.UTF8.GetBytes(jwksJson));
                return true;
            }
        }

        return false;
    }
}
