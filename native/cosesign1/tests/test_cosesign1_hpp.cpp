#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <cosesign1/cosesign1.hpp>

static std::vector<std::uint8_t> read_all_bytes(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    REQUIRE(f.good());

    f.seekg(0, std::ios::end);
    const auto len = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> bytes(len);
    if (len > 0) {
        f.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(len));
    }
    return bytes;
}

static std::filesystem::path repo_root_from_this_file()
{
    // .../native/cosesign1/tests/test_cosesign1_hpp.cpp
    auto p = std::filesystem::path(__FILE__).parent_path();
    p = p.parent_path(); // cosesign1
    p = p.parent_path(); // native
    p = p.parent_path(); // repo root
    return p;
}

TEST_CASE("abstractions.hpp: Result basics on null handle", "[cosesign1][hpp]")
{
    cosesign1::ValidationResult r;
    REQUIRE(r.ok() == false);
    REQUIRE(r.validator_name().empty());
    REQUIRE(r.failures().empty());
    REQUIRE(r.metadata().empty());
}

TEST_CASE("abstractions.hpp: string_or_empty", "[cosesign1][hpp]")
{
    REQUIRE(cosesign1::string_or_empty(nullptr).empty());
    REQUIRE(cosesign1::string_or_empty("hi") == "hi");
}

TEST_CASE("cosesign1.hpp: from_bytes overloads compile", "[cosesign1][hpp]")
{
    const std::vector<std::uint8_t> bytes_const{0x84, 0x6a, 0x53, 0x69}; // arbitrary
    auto msg1 = cosesign1::CoseSign1::from_bytes(bytes_const);

    std::vector<std::uint8_t> bytes_move{0x84, 0x6a, 0x53, 0x69};
    auto msg2 = cosesign1::CoseSign1::from_bytes(std::move(bytes_move));

    // Don't assert anything about validity; just ensure wrapper is usable.
    (void)msg1;
    (void)msg2;
}

TEST_CASE("cosesign1.hpp: verify_signature works with null pointers", "[cosesign1][hpp]")
{
    const std::vector<std::uint8_t> bytes{0x84, 0x6a, 0x53, 0x69};
    auto msg = cosesign1::CoseSign1::from_bytes(bytes);

    // This should fail deterministically (no payload, no key, invalid message), but must not crash.
    auto result = msg.verify_signature(nullptr, nullptr);
    REQUIRE(result.ok() == false);
}

TEST_CASE("cosesign1.hpp: VerificationSettings fluent builders", "[cosesign1][hpp]")
{
    cosesign1::VerificationSettings base = cosesign1::VerificationSettings::Default();

    auto no_sig = base.without_cose_signature();
    REQUIRE(no_sig.require_cose_signature == false);

    cosesign1::X509ChainOptions opt;
    opt.trust_mode = 0;
    opt.revocation_mode = 1;
    opt.allow_untrusted_roots = true;

    auto x5c = base.with_x5c_chain_validation_options(opt);
    REQUIRE(x5c.enable_x5c_chain_validator == true);
    REQUIRE(x5c.x5c_chain_options.allow_untrusted_roots == true);
}

TEST_CASE("cosesign1.hpp: verify() x5c branch executes", "[cosesign1][hpp]")
{
    const std::vector<std::uint8_t> bytes{0x84, 0x6a, 0x53, 0x69};
    auto msg = cosesign1::CoseSign1::from_bytes(bytes);

    cosesign1::X509ChainOptions opt;
    opt.trust_mode = 0;
    opt.revocation_mode = 1;
    opt.allow_untrusted_roots = false;

    // Exercise both root_views branches.
    auto settings_no_roots = cosesign1::VerificationSettings::Default().with_x5c_chain_validation_options(opt, {});
    auto r1 = msg.verify(nullptr, nullptr, settings_no_roots);
    REQUIRE(r1.ok() == false);

    std::vector<std::vector<std::uint8_t>> roots;
    roots.push_back(std::vector<std::uint8_t>{});
    auto settings_with_roots = cosesign1::VerificationSettings::Default().with_x5c_chain_validation_options(opt, std::move(roots));
    auto r2 = msg.verify(nullptr, nullptr, settings_with_roots);
    REQUIRE(r2.ok() == false);
}

TEST_CASE("mst.hpp + cosesign1.hpp: verify() MST branch executes", "[cosesign1][hpp]")
{
    const auto root = repo_root_from_this_file();
    const auto statement_path = root / "testdata" / "mst" / "azure-sdk-for-net" / "transparent_statement.cose";
    const auto jwks_path = root / "testdata" / "mst" / "azure-sdk-for-net" / "jwks_kid_mismatch.json";

    const auto statement = read_all_bytes(statement_path);
    const auto jwks = read_all_bytes(jwks_path);

    cosesign1::KeyStore store;
    REQUIRE(store.valid());

    // We don't require correctness here; we want to execute the wrapper paths.
    (void)store.AddIssuerJwks("example.invalid", jwks);

    auto msg = cosesign1::CoseSign1::from_bytes(statement);
    auto settings = cosesign1::VerificationSettings::Default().with_mst_validation_options(
        store,
        std::vector<std::string>{"example.invalid"},
        cosesign1::AuthorizedReceiptBehavior::RequireAll,
        cosesign1::UnauthorizedReceiptBehavior::FailIfPresent);

    auto res = msg.verify(nullptr, nullptr, settings);
    REQUIRE(res.ok() == false);
}

TEST_CASE("x509.hpp: X509ChainVerifier wrapper executes", "[cosesign1][hpp]")
{
    cosesign1::X509ChainOptions opt;
    opt.trust_mode = 0;
    opt.revocation_mode = 1;
    opt.allow_untrusted_roots = false;

    const std::vector<std::vector<std::uint8_t>> certs_empty;
    auto r0 = cosesign1::X509ChainVerifier::ValidateX5cChain(certs_empty, nullptr, opt);
    REQUIRE(r0.ok() == false);

    std::vector<std::vector<std::uint8_t>> certs_one;
    certs_one.push_back(std::vector<std::uint8_t>{});
    std::vector<std::vector<std::uint8_t>> roots_one;
    roots_one.push_back(std::vector<std::uint8_t>{});

    auto r1 = cosesign1::X509ChainVerifier::ValidateX5cChain(certs_one, &roots_one, opt);
    REQUIRE(r1.ok() == false);
}

TEST_CASE("cosesign1.hpp: is_detached_payload helper executes", "[cosesign1][hpp]")
{
    const auto root = repo_root_from_this_file();
    const auto statement_path = root / "testdata" / "mst" / "azure-sdk-for-net" / "transparent_statement.cose";
    const auto statement = read_all_bytes(statement_path);

    auto msg = cosesign1::CoseSign1::from_bytes(statement);
    (void)msg.is_detached_payload();
    SUCCEED();
}

TEST_CASE("cosesign1.hpp: detail istream callbacks are usable", "[cosesign1][hpp]")
{
    std::stringstream ss;
    ss << "abcdef";

    cosesign1::detail::IstreamReaderCtx ctx{ &ss };

    std::uint8_t buf[3]{};
    size_t bytes_read = 0;
    REQUIRE(cosesign1::detail::istream_read(&ctx, buf, sizeof(buf), &bytes_read) == 0);
    REQUIRE(bytes_read == sizeof(buf));

    uint64_t new_pos = 0;
    REQUIRE(cosesign1::detail::istream_seek(&ctx, 0, 0, &new_pos) == 0);
    REQUIRE(new_pos == 0);

    // Invalid origin should fail.
    REQUIRE(cosesign1::detail::istream_seek(&ctx, 0, 99, &new_pos) == 1);

    // A bad stream should surface as an error from read.
    ss.setstate(std::ios::badbit);
    bytes_read = 0;
    REQUIRE(cosesign1::detail::istream_read(&ctx, buf, sizeof(buf), &bytes_read) == 1);
}

TEST_CASE("mst.hpp: KeyStore move semantics", "[cosesign1][hpp]")
{
    cosesign1::KeyStore ks;
    REQUIRE(ks.valid());

    cosesign1::KeyStore moved = std::move(ks);
    REQUIRE(moved.valid());
    REQUIRE(ks.valid() == false);
}

TEST_CASE("cosesign1.hpp: MST verify with empty domain list", "[cosesign1][hpp]")
{
    const auto root = repo_root_from_this_file();
    const auto statement_path = root / "testdata" / "mst" / "azure-sdk-for-net" / "transparent_statement.cose";
    const auto statement = read_all_bytes(statement_path);

    cosesign1::KeyStore store;
    auto msg = cosesign1::CoseSign1::from_bytes(statement);

    auto settings = cosesign1::VerificationSettings::Default().with_mst_validation_options(
        store,
        std::vector<std::string>{},
        cosesign1::AuthorizedReceiptBehavior::VerifyAnyMatching,
        cosesign1::UnauthorizedReceiptBehavior::IgnoreAll);

    auto res = msg.verify(nullptr, nullptr, settings);
    REQUIRE(res.ok() == false);
}
