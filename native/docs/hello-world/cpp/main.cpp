//
// Minimal consumer example for the cosesign1 native C++ projection.
//
// This sample:
// - reads input files into memory
// - parses COSE_Sign1 bytes into cosesign1::CoseSign1
// - calls msg.verify_signature(...) or msg.verify(...)
//
// For build instructions, see:
// - docs/NativeCxx.md
// - native/docs/hello-world/cpp/README.md
//

#include <cosesign1/cosesign1.hpp>

#include <cstdint>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void usage_and_exit(const char* exe) {
    std::cerr << "Usage:\n";
    std::cerr << "  " << exe << " key --cose <file> --public-key <der> [--payload <file>]\n";
    std::cerr << "  " << exe << " x5c --cose <file> [--payload <file>] --trust <system|custom> [--root <der>] [--revocation <online|offline|none>] [--allow-untrusted]\n";
    std::cerr << "  " << exe << " mst --statement <file> --issuer-host <host> --jwks <file>\n";
    std::exit(2);
}

static bool has_flag(int argc, char** argv, const std::string& flag) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == flag) return true;
    }
    return false;
}

static std::string get_flag_value(int argc, char** argv, const std::string& flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (argv[i] == flag) return argv[i + 1];
    }
    return {};
}

static std::vector<std::string> get_flag_values(int argc, char** argv, const std::string& flag) {
    std::vector<std::string> out;
    for (int i = 1; i + 1 < argc; ++i) {
        if (argv[i] == flag) out.push_back(argv[i + 1]);
    }
    return out;
}

static std::vector<std::uint8_t> read_file_bytes_or_exit(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open file: " << path << "\n";
        std::exit(2);
    }

    f.seekg(0, std::ios::end);
    const auto size = f.tellg();
    if (size < 0) {
        std::cerr << "Failed to read file size: " << path << "\n";
        std::exit(2);
    }
    f.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> bytes(static_cast<size_t>(size));
    if (!bytes.empty()) {
        f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!f) {
            std::cerr << "Failed to read file: " << path << "\n";
            std::exit(2);
        }
    }
    return bytes;
}

static void print_validation_result(const cosesign1::ValidationResult& r) {
    std::cout << "is_valid: " << (r.ok() ? "true" : "false") << "\n";
    std::cout << "validator: " << r.validator_name() << "\n";

    const auto md = r.metadata();
    if (!md.empty()) {
        std::cout << "metadata:\n";
        std::vector<std::string> keys;
        keys.reserve(md.size());
        for (const auto& kv : md) keys.push_back(kv.first);
        std::sort(keys.begin(), keys.end());
        for (const auto& k : keys) {
            const auto it = md.find(k);
            if (it != md.end()) {
                std::cout << "  " << it->first << ": " << it->second << "\n";
            }
        }
    }

    const auto failures = r.failures();
    if (!failures.empty()) {
        std::cout << "failures:\n";
        for (const auto& f : failures) {
            if (!f.error_code.empty()) {
                std::cout << "- " << f.error_code << ": " << f.message << "\n";
            } else {
                std::cout << "- " << f.message << "\n";
            }
        }
    }
}

int main(int argc, char** argv) {
    const char* exe = (argc > 0 && argv && argv[0]) ? argv[0] : "cosesign1_cpp_hello_world";
    if (argc < 2) usage_and_exit(exe);

    const std::string mode = argv[1];

    if (mode == "key") {
        const auto cose_path = get_flag_value(argc, argv, "--cose");
        const auto public_key_path = get_flag_value(argc, argv, "--public-key");
        const auto payload_path = get_flag_value(argc, argv, "--payload");
        if (cose_path.empty() || public_key_path.empty()) usage_and_exit(exe);

        const auto cose = read_file_bytes_or_exit(cose_path);
        const auto public_key = read_file_bytes_or_exit(public_key_path);

        std::vector<std::uint8_t> payload;
        const std::vector<std::uint8_t>* payload_ptr = nullptr;
        if (!payload_path.empty()) {
            payload = read_file_bytes_or_exit(payload_path);
            payload_ptr = &payload;
        }

        auto msg = cosesign1::CoseSign1::from_bytes(cose);
        if (msg.is_detached_payload() && payload_ptr == nullptr) {
            std::cerr << "COSE payload is detached (null); provide --payload <file>\n";
            return 1;
        }

        // Signature-only verification.
        auto r = msg.verify_signature(payload_ptr, &public_key);
        print_validation_result(r);
        return r.ok() ? 0 : 3;
    }

    if (mode == "x5c") {
        const auto cose_path = get_flag_value(argc, argv, "--cose");
        const auto payload_path = get_flag_value(argc, argv, "--payload");
        const auto trust = get_flag_value(argc, argv, "--trust");
        const auto root_path = get_flag_value(argc, argv, "--root");
        const auto revocation = get_flag_value(argc, argv, "--revocation");
        const bool allow_untrusted = has_flag(argc, argv, "--allow-untrusted");
        if (cose_path.empty() || trust.empty()) usage_and_exit(exe);

        const auto cose = read_file_bytes_or_exit(cose_path);
        auto msg = cosesign1::CoseSign1::from_bytes(cose);

        std::vector<std::uint8_t> payload;
        const std::vector<std::uint8_t>* payload_ptr = nullptr;
        if (!payload_path.empty()) {
            payload = read_file_bytes_or_exit(payload_path);
            payload_ptr = &payload;
        }

        if (msg.is_detached_payload() && payload_ptr == nullptr) {
            std::cerr << "COSE payload is detached (null); provide --payload <file>\n";
            return 1;
        }

        cosesign1::X509ChainOptions opt;
        opt.allow_untrusted_roots = allow_untrusted;
        if (trust == "system") {
            opt.trust_mode = 0;
        } else if (trust == "custom") {
            opt.trust_mode = 1;
        } else {
            usage_and_exit(exe);
        }

        if (revocation.empty() || revocation == "online") {
            opt.revocation_mode = revocation.empty() ? 0 : 1;
        } else if (revocation == "offline") {
            opt.revocation_mode = 2;
        } else if (revocation == "none") {
            opt.revocation_mode = 0;
        } else {
            usage_and_exit(exe);
        }

        std::vector<std::vector<std::uint8_t>> roots;
        if (opt.trust_mode == 1) {
            if (root_path.empty()) {
                std::cerr << "--trust custom requires --root <der>\n";
                return 2;
            }
            roots.push_back(read_file_bytes_or_exit(root_path));
        }

        // Full verification:
        // - signature uses the leaf public key from x5c
        // - chain trust policy is enforced after signature verification
        const auto settings = cosesign1::VerificationSettings::Default()
            .with_x5c_chain_validation_options(opt, std::move(roots));

        auto r = msg.verify(payload_ptr, nullptr, settings);
        print_validation_result(r);
        return r.ok() ? 0 : 3;
    }

    if (mode == "mst") {
        const auto stmt_path = get_flag_value(argc, argv, "--statement");
        const auto issuer_host = get_flag_value(argc, argv, "--issuer-host");
        const auto jwks_path = get_flag_value(argc, argv, "--jwks");
        if (stmt_path.empty() || issuer_host.empty() || jwks_path.empty()) usage_and_exit(exe);

        const auto stmt = read_file_bytes_or_exit(stmt_path);
        const auto jwks = read_file_bytes_or_exit(jwks_path);

        cosesign1::KeyStore store;
        auto add = store.AddIssuerJwks(issuer_host, jwks);
        if (!add.ok()) {
            print_validation_result(cosesign1::ValidationResult(reinterpret_cast<cosesign1_validation_result*>(add.release())));
            return 3;
        }

        std::vector<std::string> authorized_domains;
        authorized_domains.push_back(issuer_host);

        auto msg = cosesign1::CoseSign1::from_bytes(stmt);
        const auto settings = cosesign1::VerificationSettings::Default()
            .without_cose_signature()
            .with_mst_validation_options(
                store,
                authorized_domains,
                cosesign1::AuthorizedReceiptBehavior::VerifyAnyMatching,
                cosesign1::UnauthorizedReceiptBehavior::VerifyAll);

        auto r = msg.verify(nullptr, nullptr, settings);
        print_validation_result(r);
        return r.ok() ? 0 : 3;
    }

    (void)&has_flag; // reserved for future flags
    usage_and_exit(exe);
}

