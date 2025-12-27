//
// Minimal consumer example for the cosesign1 native C ABI.
//
// This program is intentionally small and pragmatic:
// - reads input files into memory
// - calls into the C ABI verification APIs
// - prints a ValidationResult-like summary
//
// For build instructions, see:
// - docs/NativeCxx.md
// - native/docs/hello-world/c/README.md
//

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cosesign1/abstractions.h"
#include "cosesign1/cosesign1.h"
#include "cosesign1/mst.h"
#include "cosesign1/x509.h"

static void usage(const char* exe) {
    fprintf(stderr,
        "Usage:\n"
        "  %s key --cose <file> --public-key <der> [--payload <file>]\n"
        "  %s x5c --cose <file> [--payload <file>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]\n"
        "  %s mst --statement <file> --issuer-host <host> --jwks <file>\n",
        exe,
        exe,
        exe);
}

static int read_all_bytes(const char* path, uint8_t** out, size_t* out_len) {
    *out = NULL;
    *out_len = 0;

    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }

    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return 1;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf && sz != 0) {
        fclose(f);
        return 1;
    }

    size_t read = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (read != (size_t)sz) {
        free(buf);
        return 1;
    }

    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int is_detached_payload(const uint8_t* cose, size_t cose_len, bool* out_detached) {
    *out_detached = false;

    cosesign1_abstractions_info info;
    cosesign1_abstractions_result* r = cosesign1_abstractions_inspect(cose, cose_len, &info);
    if (!r) {
        return 1;
    }

    bool ok = cosesign1_abstractions_result_is_valid(r);
    if (ok) {
        *out_detached = info.is_detached;
    }

    cosesign1_abstractions_result_free(r);
    return ok ? 0 : 1;
}

static void print_validation_result(const cosesign1_validation_result* res) {
    if (!res) {
        printf("is_valid: false\n");
        printf("validator: <null>\n");
        return;
    }

    printf("is_valid: %s\n", cosesign1_validation_result_is_valid(res) ? "true" : "false");
    printf("validator: %s\n", cosesign1_validation_result_validator_name(res));

    // Metadata is an optional key-value bag for higher-level validators (e.g., MST).
    size_t mc = cosesign1_validation_result_metadata_count(res);
    for (size_t i = 0; i < mc; i++) {
        cosesign1_kv_view kv = cosesign1_validation_result_metadata_at(res, i);
        printf("%s: %s\n", kv.key, kv.value);
    }

    size_t fc = cosesign1_validation_result_failure_count(res);
    if (fc > 0) {
        printf("failures:\n");
        for (size_t i = 0; i < fc; i++) {
            cosesign1_failure_view f = cosesign1_validation_result_failure_at(res, i);
            const char* code = f.error_code ? f.error_code : "UNKNOWN";
            printf("- %s: %s\n", code, f.message);
        }
    }
}

static bool streq(const char* a, const char* b) {
    return strcmp(a, b) == 0;
}

static const char* get_arg_value(int argc, char** argv, const char* key) {
    for (int i = 0; i + 1 < argc; i++) {
        if (streq(argv[i], key)) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static bool has_flag(int argc, char** argv, const char* flag) {
    for (int i = 0; i < argc; i++) {
        if (streq(argv[i], flag)) {
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char* mode = argv[1];

    if (streq(mode, "key")) {
        const char* cose_path = get_arg_value(argc, argv, "--cose");
        const char* pk_path = get_arg_value(argc, argv, "--public-key");
        const char* payload_path = get_arg_value(argc, argv, "--payload");

        if (!cose_path || !pk_path) {
            usage(argv[0]);
            return 1;
        }

        uint8_t* cose = NULL;
        size_t cose_len = 0;
        if (read_all_bytes(cose_path, &cose, &cose_len) != 0) {
            fprintf(stderr, "failed to read --cose file\n");
            return 1;
        }

        uint8_t* pk = NULL;
        size_t pk_len = 0;
        if (read_all_bytes(pk_path, &pk, &pk_len) != 0) {
            fprintf(stderr, "failed to read --public-key file\n");
            free(cose);
            return 1;
        }

        bool detached = false;
        if (is_detached_payload(cose, cose_len, &detached) == 0 && detached && !payload_path) {
            fprintf(stderr, "detached payload requires --payload\n");
            free(pk);
            free(cose);
            return 1;
        }

        uint8_t* payload = NULL;
        size_t payload_len = 0;
        if (payload_path) {
            if (read_all_bytes(payload_path, &payload, &payload_len) != 0) {
                fprintf(stderr, "failed to read --payload file\n");
                free(pk);
                free(cose);
                return 1;
            }
        }

        // Signature-only verification (no x5c trust, no MST).
        cosesign1_validation_result* res = cosesign1_validation_verify_signature(
            cose,
            cose_len,
            payload,
            payload_len,
            pk,
            pk_len);

        print_validation_result(res);

        bool ok = cosesign1_validation_result_is_valid(res);

        cosesign1_validation_result_free(res);
        free(payload);
        free(pk);
        free(cose);
        return ok ? 0 : 3;
    }

    if (streq(mode, "x5c")) {
        const char* cose_path = get_arg_value(argc, argv, "--cose");
        const char* payload_path = get_arg_value(argc, argv, "--payload");
        const char* trust = get_arg_value(argc, argv, "--trust");
        const char* root_path = get_arg_value(argc, argv, "--root");
        const char* rev = get_arg_value(argc, argv, "--revocation");
        bool allow_untrusted = has_flag(argc, argv, "--allow-untrusted");

        if (!cose_path || !trust) {
            usage(argv[0]);
            return 1;
        }

        uint8_t* cose = NULL;
        size_t cose_len = 0;
        if (read_all_bytes(cose_path, &cose, &cose_len) != 0) {
            fprintf(stderr, "failed to read --cose file\n");
            return 1;
        }

        bool detached = false;
        if (is_detached_payload(cose, cose_len, &detached) == 0 && detached && !payload_path) {
            fprintf(stderr, "detached payload requires --payload\n");
            free(cose);
            return 1;
        }

        uint8_t* payload = NULL;
        size_t payload_len = 0;
        if (payload_path) {
            if (read_all_bytes(payload_path, &payload, &payload_len) != 0) {
                fprintf(stderr, "failed to read --payload file\n");
                free(cose);
                return 1;
            }
        }

        cosesign1_byte_view roots[1];
        size_t roots_count = 0;
        uint8_t* root_bytes = NULL;
        size_t root_len = 0;

        int trust_mode = 0;
        if (streq(trust, "system")) {
            trust_mode = 0;
        } else if (streq(trust, "custom")) {
            trust_mode = 1;
            if (root_path) {
                if (read_all_bytes(root_path, &root_bytes, &root_len) != 0) {
                    fprintf(stderr, "failed to read --root file\n");
                    free(payload);
                    free(cose);
                    return 1;
                }
                roots[0].data = root_bytes;
                roots[0].len = root_len;
                roots_count = 1;
            }
        } else {
            fprintf(stderr, "--trust must be system or custom\n");
            free(payload);
            free(cose);
            return 1;
        }

        int revocation_mode = 0;
        if (!rev || streq(rev, "none")) {
            revocation_mode = 0;
        } else if (streq(rev, "online")) {
            revocation_mode = 1;
        } else if (streq(rev, "offline")) {
            revocation_mode = 2;
        } else {
            fprintf(stderr, "--revocation must be online, offline, or none\n");
            free(root_bytes);
            free(payload);
            free(cose);
            return 1;
        }

        cosesign1_x509_chain_options opt;
        opt.trust_mode = trust_mode;
        opt.revocation_mode = revocation_mode;
        opt.allow_untrusted_roots = allow_untrusted;

        // Verify with embedded x5c:
        // - signature uses the leaf certificate public key
        // - chain trust policy is applied after signature verification
        cosesign1_x509_result* xres = cosesign1_x509_verify_cose_sign1_with_x5c_chain(
            cose,
            cose_len,
            payload,
            payload_len,
            roots_count ? roots : NULL,
            roots_count,
            opt);

        // x509 result is ABI-compatible with validation result.
        print_validation_result((const cosesign1_validation_result*)xres);

        bool ok = cosesign1_x509_result_is_valid(xres);

        cosesign1_x509_result_free(xres);
        free(root_bytes);
        free(payload);
        free(cose);
        return ok ? 0 : 3;
    }

    if (streq(mode, "mst")) {
        const char* statement_path = get_arg_value(argc, argv, "--statement");
        const char* issuer_host = get_arg_value(argc, argv, "--issuer-host");
        const char* jwks_path = get_arg_value(argc, argv, "--jwks");

        if (!statement_path || !issuer_host || !jwks_path) {
            usage(argv[0]);
            return 1;
        }

        uint8_t* statement = NULL;
        size_t statement_len = 0;
        if (read_all_bytes(statement_path, &statement, &statement_len) != 0) {
            fprintf(stderr, "failed to read --statement file\n");
            return 1;
        }

        uint8_t* jwks = NULL;
        size_t jwks_len = 0;
        if (read_all_bytes(jwks_path, &jwks, &jwks_len) != 0) {
            fprintf(stderr, "failed to read --jwks file\n");
            free(statement);
            return 1;
        }

        // Offline MST verification uses a caller-provided keystore.
        cosesign1_mst_keystore* store = cosesign1_mst_keystore_new();
        if (!store) {
            fprintf(stderr, "failed to create MST keystore\n");
            free(jwks);
            free(statement);
            return 1;
        }

        cosesign1_mst_result* add_res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer_host, jwks, jwks_len);
        if (!cosesign1_mst_result_is_valid(add_res)) {
            // print add errors and exit.
            print_validation_result((const cosesign1_validation_result*)add_res);
            cosesign1_mst_result_free(add_res);
            cosesign1_mst_keystore_free(store);
            free(jwks);
            free(statement);
            return 3;
        }
        cosesign1_mst_result_free(add_res);

        cosesign1_mst_verification_options opt;
        opt.authorized_receipt_behavior = 0;   // VerifyAnyMatching
        opt.unauthorized_receipt_behavior = 0; // VerifyAll

        // The statement declares issuer domains; this example authorizes the single issuer provided.
        cosesign1_string_view authorized_domains[1];
        authorized_domains[0].data = issuer_host;

        cosesign1_mst_result* res = cosesign1_mst_verify_transparent_statement(
            store,
            statement,
            statement_len,
            authorized_domains,
            1,
            opt);

        print_validation_result((const cosesign1_validation_result*)res);

        bool ok = cosesign1_mst_result_is_valid(res);

        cosesign1_mst_result_free(res);
        cosesign1_mst_keystore_free(store);
        free(jwks);
        free(statement);
        return ok ? 0 : 3;
    }

    usage(argv[0]);
    return 1;
}
