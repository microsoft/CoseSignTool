// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Infrastructure;

using System;
using System.IO;
using System.Text;

/// <summary>
/// Format-agnostic enumeration of the trust-policy frontends exercised by this suite. Tests
/// declare a matrix cell once per scenario and parameterise on this enum; the
/// <see cref="PolicyDocumentBuilder"/> emits the appropriate file for each format.
/// </summary>
public enum PolicyFormat
{
    /// <summary>
    /// <c>cose-tp-json/v1</c> frontend (.coseTrustPolicy.json).
    /// </summary>
    Json = 0,

    /// <summary>
    /// <c>cose-tp-rego/v1</c> frontend (.coseTrustPolicy.rego). The Rego file lowers to the
    /// same canonical IR shape as the JSON form, so the same body strings serve both.
    /// </summary>
    Rego = 1,
}

/// <summary>
/// Authors a trust-policy document on disk in either the JSON or Rego frontend format. The
/// builder targets one canonical scenario per test cell — instead of a generic AST builder the
/// helper exposes scenario-specific factories that produce equivalent JSON + Rego variants.
/// This keeps the matrix cells readable and guarantees the cross-format equivalence assertion
/// has byte-comparable inputs (only frontend wrapper changes between formats).
/// </summary>
public static class PolicyDocumentBuilder
{
    private const string RegoPackageHeader = "package cose_trust_policy\n\n";
    private const string RegoPolicyOpener = "policy := ";

    /// <summary>
    /// Writes the supplied document body to a fresh temp file with the appropriate extension
    /// and returns its absolute path. Caller is responsible for cleanup (most tests rely on
    /// <see cref="SignedFixture"/> to clean its directory; standalone documents go under the
    /// NUnit test directory so test failures keep the artefact for triage).
    /// </summary>
    public static string Write(PolicyFormat format, string body, string filenameStem)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentException.ThrowIfNullOrEmpty(filenameStem);

        string ext = format switch
        {
            PolicyFormat.Json => ".coseTrustPolicy.json",
            PolicyFormat.Rego => ".coseTrustPolicy.rego",
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };

        string root = Path.Combine(TestContext.CurrentContext.TestDirectory, "policy-output");
        Directory.CreateDirectory(root);
        string path = Path.Combine(root, filenameStem + "-" + Guid.NewGuid().ToString("N") + ext);
        File.WriteAllText(path, body, Encoding.UTF8);
        return path;
    }

    /// <summary>
    /// Wraps a JSON object literal as a Rego policy rule. Rego policies in this dialect have a
    /// fixed shape: a package declaration plus a single <c>policy := { ... }</c> rule whose body
    /// is JSON-equivalent (no Rego comprehensions or expressions, by design).
    /// </summary>
    public static string WrapAsRego(string jsonObjectBody)
    {
        ArgumentNullException.ThrowIfNull(jsonObjectBody);
        return string.Concat(RegoPackageHeader, RegoPolicyOpener, jsonObjectBody, "\n");
    }

    // ---------------- canonical scenario factories ----------------
    // Each method returns a (json, rego) pair so the caller can persist either or both to disk.
    // The Rego body lifts the same JSON object literal so cross-format equivalence holds at the
    // IR level (Phase 4's contract). Where the JSON form uses an outer "frontend" discriminator
    // it is omitted — the loader treats the discriminator as optional but its presence would
    // still translate identically.

    /// <summary>
    /// Single requirement: <c>x509-chain-trusted/v1 -> is_trusted=true</c>.
    /// </summary>
    public static (string Json, string Rego) X509ChainTrusted()
    {
        const string body = """
        {
            "primary_signing_key": {
                "fact": "x509-chain-trusted/v1",
                "predicate": {"is_trusted": true}
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// Single requirement: <c>x509-cert-identity-allowed/v1 -> is_allowed=true</c>. Exercises
    /// the always-pass case where the X509 trust pack has no identity pinning configured.
    /// </summary>
    public static (string Json, string Rego) X509IdentityIsAllowedTrue()
    {
        const string body = """
        {
            "primary_signing_key": {
                "fact": "x509-cert-identity-allowed/v1",
                "predicate": {"is_allowed": true}
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// Inverted requirement: <c>x509-cert-identity-allowed/v1 -> is_allowed=false</c>. Without
    /// CLI-side pinning the produced fact always asserts <c>is_allowed=true</c>, so the
    /// predicate fails and the trust plan denies — the deny-list match scenario.
    /// </summary>
    public static (string Json, string Rego) X509IdentityIsAllowedFalse()
    {
        const string body = """
        {
            "primary_signing_key": {
                "fact": "x509-cert-identity-allowed/v1",
                "predicate": {"is_allowed": false}
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// EKU OID requirement. The fact set surfaces every EKU on the leaf cert; the policy passes
    /// when at least one fact carries the expected OID.
    /// </summary>
    public static (string Json, string Rego) X509EkuOid(string oid)
    {
        ArgumentException.ThrowIfNullOrEmpty(oid);
        string body = $$"""
        {
            "primary_signing_key": {
                "fact": "x509-cert-eku/v1",
                "predicate": {"oid_value": "{{oid}}"}
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// Parametrised CN allow-list. Produces an x509-cert-identity/v1 predicate that matches
    /// when the bound parameter equals the leaf's subject CN. The policy succeeds for the
    /// matching binding and denies otherwise.
    /// </summary>
    public static (string Json, string Rego) X509SubjectEqualsParam(string paramName, string defaultCn)
    {
        ArgumentException.ThrowIfNullOrEmpty(paramName);
        ArgumentException.ThrowIfNullOrEmpty(defaultCn);

        // Use the path-operator predicate with operator=Equals against $.subject. The fact's
        // Subject property is the full DN, so the param value supplied by the test must match
        // the cert's Subject string verbatim (e.g. "CN=Test Leaf: foo").
        string body = $$"""
        {
            "primary_signing_key": {
                "fact": "x509-cert-identity/v1",
                "predicate": {
                    "operator": "Equals",
                    "path": "$.subject",
                    "value": {"$param": "{{paramName}}", "default": "{{defaultCn}}"}
                }
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// MST scope: receipt must be present (boolean property assertion).
    /// </summary>
    public static (string Json, string Rego) MstReceiptPresent()
    {
        const string body = """
        {
            "any_counter_signature": {
                "on_empty": "deny",
                "fact": "mst-receipt-present/v1",
                "predicate": {"is_present": true}
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// MST scope: receipt must be cryptographically trusted. AND-combines with present.
    /// </summary>
    public static (string Json, string Rego) MstReceiptPresentAndTrusted()
    {
        const string body = """
        {
            "any_counter_signature": {
                "on_empty": "deny",
                "all_of": [
                    {"fact": "mst-receipt-present/v1", "predicate": {"is_present": true}},
                    {"fact": "mst-receipt-trusted/v1", "predicate": {"is_trusted": true}}
                ]
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// MST scope: receipt issuer host must equal the supplied literal (no parameterisation).
    /// Uses the path-operator predicate with operator=Contains against the fact's Hosts array.
    /// </summary>
    public static (string Json, string Rego) MstReceiptIssuerHost(string host)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        string body = $$"""
        {
            "any_counter_signature": {
                "on_empty": "deny",
                "fact": "mst-receipt-issuer-host/v1",
                "predicate": {
                    "operator": "Contains",
                    "path": "$.hosts",
                    "value": "{{host}}"
                }
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// MST scope: parametrised issuer-host match. The bound parameter supplies the expected
    /// host name; mismatched bindings cause a deny via the Contains predicate failing.
    /// </summary>
    public static (string Json, string Rego) MstReceiptIssuerHostParam(string paramName, string defaultHost)
    {
        ArgumentException.ThrowIfNullOrEmpty(paramName);
        ArgumentException.ThrowIfNullOrEmpty(defaultHost);

        string body = $$"""
        {
            "any_counter_signature": {
                "on_empty": "deny",
                "fact": "mst-receipt-issuer-host/v1",
                "predicate": {
                    "operator": "Contains",
                    "path": "$.hosts",
                    "value": {"$param": "{{paramName}}", "default": "{{defaultHost}}"}
                }
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// MST scope: parametrised issuer-host match WITHOUT a default. Drives the unbound-parameter
    /// path (TPX400) when the caller forgets to supply a binding.
    /// </summary>
    public static (string Json, string Rego) MstReceiptIssuerHostUnboundParam(string paramName)
    {
        ArgumentException.ThrowIfNullOrEmpty(paramName);

        string body = $$"""
        {
            "any_counter_signature": {
                "on_empty": "deny",
                "fact": "mst-receipt-issuer-host/v1",
                "predicate": {
                    "operator": "Contains",
                    "path": "$.hosts",
                    "value": {"$param": "{{paramName}}"}
                }
            }
        }
        """;
        return (body, WrapAsRego(body));
    }

    /// <summary>
    /// Trivial allow-all message scope. Used by D8 override looser-doc tests where the policy
    /// must accept everything that survived signature verification.
    /// </summary>
    public static (string Json, string Rego) MessageAllowAll()
    {
        const string body = """
        {
            "message": {"allow_all": true}
        }
        """;
        return (body, WrapAsRego(body));
    }
}
