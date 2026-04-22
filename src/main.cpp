// IDA Pro 9.x license keygen + binary patcher.
//
// Generates a signed `idapro.hexlic` and patches IDA's RSA modulus in
// libida/libida32 (.dll/.dylib/.so) so the forged license validates.
// Functional mirror of scripts/ida_keygen.py.
//
// Crack: IDA verifies signatures with a 1024-bit RSA modulus embedded in its
// binary. Flipping one nibble of that modulus (5C -> CB at byte 3) turns it
// into a different N whose private exponent we know, so we can sign any
// payload and have IDA accept it.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace fs = std::filesystem;

// =============================================================================
// Crypto constants  (hex strings are little-endian, matching IDA's wire format)
// =============================================================================

// Defined for reference: this is the original modulus IDA ships with. The
// crack flips one nibble (5C -> CB at byte 3) to obtain PUB_MODULUS_PATCHED,
// whose private exponent we know.
[[maybe_unused]] constexpr std::string_view PUB_MODULUS_HEXRAYS =
    "edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f"
    "4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5ddd"
    "d91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e3"
    "3c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93";

constexpr std::string_view PUB_MODULUS_PATCHED =
    "edfd42cbf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f"
    "4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5ddd"
    "d91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e3"
    "3c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93";

constexpr std::string_view PRIVATE_KEY =
    "77c86abbb7f3bb134436797b68ff47beb1a5457816608dbfb72641814dd464dd"
    "640d711d5732d3017a1c4e63d835822f00a4eab619a2c4791cf33f9f57f9c2ae"
    "4d9eed9981e79ac9b8f8a411f68f25b9f0c05d04d11e22a3a0d8d4672b56a61f"
    "1532282ff4e4e74759e832b70e98b9d102d07e9fb9ba8d15810b144970029874";

// 6-byte signature at the start of the modulus blob in IDA's binary.
static const std::vector<uint8_t> ORIGINAL_MAGIC = {0xED, 0xFD, 0x42, 0x5C, 0xF9, 0x78};
static const std::vector<uint8_t> PATCHED_MAGIC  = {0xED, 0xFD, 0x42, 0xCB, 0xF9, 0x78};

static const std::vector<std::string> DECOMPILER_ADDONS = {
    "HEXX86",   "HEXX64",
    "HEXARM",   "HEXARM64",
    "HEXMIPS",  "HEXMIPS64",
    "HEXPPC",   "HEXPPC64",
    "HEXRV64",
    "HEXARC",   "HEXARC64",
};

constexpr std::string_view OUTPUT_FILENAME = "idapro.hexlic";

// Tried in order; first one that exists is used as the license template.
static const std::vector<fs::path> LICENSE_TEMPLATE_PATHS = {
    "licenses.json",
    "data/licenses.json",
    "../data/licenses.json",
};

// =============================================================================
// Hex / bignum helpers
// =============================================================================

static std::vector<uint8_t> hex_to_bytes(std::string_view hex)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const char buf[3] = {hex[i], hex[i + 1], '\0'};
        bytes.push_back(static_cast<uint8_t>(std::strtol(buf, nullptr, 16)));
    }
    return bytes;
}

static std::string bytes_to_hex_upper(const std::vector<uint8_t>& data)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

// Hex string is a sequence of little-endian bytes; build a BIGNUM from them.
static BIGNUM* le_hex_to_bn(std::string_view hex)
{
    auto bytes = hex_to_bytes(hex);
    std::reverse(bytes.begin(), bytes.end());
    return BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
}

static std::vector<uint8_t> bn_to_le_bytes(const BIGNUM* bn)
{
    std::vector<uint8_t> buf(BN_num_bytes(bn));
    BN_bn2bin(bn, buf.data());
    std::reverse(buf.begin(), buf.end());
    return buf;
}

// =============================================================================
// JSON canonicalization  (mirror of Python's json.dumps(sort_keys=True, separators=(",", ":")))
// =============================================================================

static void sort_json(const rapidjson::Value& src,
                      rapidjson::Value& dst,
                      rapidjson::Document::AllocatorType& allocator)
{
    if (src.IsObject()) {
        dst.SetObject();
        std::map<std::string, const rapidjson::Value*> sorted;
        for (auto it = src.MemberBegin(); it != src.MemberEnd(); ++it)
            sorted[it->name.GetString()] = &it->value;
        for (const auto& [name, value] : sorted) {
            rapidjson::Value k(name.c_str(), allocator);
            rapidjson::Value v;
            sort_json(*value, v, allocator);
            dst.AddMember(k, v, allocator);
        }
    } else if (src.IsArray()) {
        dst.SetArray();
        for (const auto& v : src.GetArray()) {
            rapidjson::Value e;
            sort_json(v, e, allocator);
            dst.PushBack(e, allocator);
        }
    } else {
        dst.CopyFrom(src, allocator);
    }
}

static std::string canonical_json(const rapidjson::Value& v)
{
    rapidjson::Document scratch;
    rapidjson::Value sorted;
    sort_json(v, sorted, scratch.GetAllocator());

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    sorted.Accept(writer);
    return buffer.GetString();
}

// =============================================================================
// License manipulation
// =============================================================================

static std::expected<rapidjson::Document, std::string>
load_license_template()
{
    for (const auto& candidate : LICENSE_TEMPLATE_PATHS) {
        std::ifstream f(candidate, std::ios::binary);
        if (!f) continue;

        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());

        rapidjson::Document d;
        if (d.Parse<rapidjson::kParseCommentsFlag>(content.c_str()).HasParseError()) {
            return std::unexpected("JSON parse error in " + candidate.string()
                + " at offset " + std::to_string(d.GetErrorOffset()));
        }
        std::cout << "Loaded license template from " << candidate << "\n";
        return d;
    }
    std::string msg = "could not find license template (tried: ";
    for (size_t i = 0; i < LICENSE_TEMPLATE_PATHS.size(); ++i) {
        if (i) msg += ", ";
        msg += LICENSE_TEMPLATE_PATHS[i].string();
    }
    return std::unexpected(msg + ")");
}

static void add_every_decompiler(rapidjson::Document& doc)
{
    auto& allocator = doc.GetAllocator();
    auto& license = doc["payload"]["licenses"][0];
    const std::string parent_id = license["id"].GetString();
    auto add_ons = license["add_ons"].GetArray();

    int i = 1;
    for (const auto& code : DECOMPILER_ADDONS) {
        char id_buf[32];
        std::snprintf(id_buf, sizeof(id_buf), "48-1337-0000-%02d", i++);

        rapidjson::Value entry(rapidjson::kObjectType);
        entry.AddMember("id",         rapidjson::Value(id_buf,           allocator), allocator);
        entry.AddMember("code",       rapidjson::Value(code.c_str(),     allocator), allocator);
        entry.AddMember("owner",      rapidjson::Value(parent_id.c_str(),allocator), allocator);
        entry.AddMember("start_date", rapidjson::Value("2024-08-10 00:00:00"), allocator);
        entry.AddMember("end_date",   rapidjson::Value("2083-12-31 23:59:59"), allocator);
        add_ons.PushBack(entry, allocator);
    }
}

// =============================================================================
// Signing  (textbook RSA: m^d mod n, with little-endian byte conventions)
// =============================================================================

static std::vector<uint8_t> rsa_sign(const std::vector<uint8_t>& message)
{
    BIGNUM* n = le_hex_to_bn(PUB_MODULUS_PATCHED);
    BIGNUM* d = le_hex_to_bn(PRIVATE_KEY);
    BIGNUM* m = BN_bin2bn(message.data(), static_cast<int>(message.size()), nullptr);
    BIGNUM* r = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_mod_exp(r, m, d, n, ctx);
    auto out = bn_to_le_bytes(r);

    BN_CTX_free(ctx);
    BN_free(m); BN_free(r); BN_free(n); BN_free(d);
    return out;
}

// Build the 128-byte block (33 bytes 0x42 || 32-byte SHA-256) and sign it.
static std::string sign_hexlic(const rapidjson::Value& payload)
{
    rapidjson::Document wrapper;
    wrapper.SetObject();
    auto& alloc = wrapper.GetAllocator();
    rapidjson::Value pcopy;
    pcopy.CopyFrom(payload, alloc);
    wrapper.AddMember("payload", pcopy, alloc);

    const auto canonical = canonical_json(wrapper);

    std::vector<uint8_t> block(128, 0x00);
    std::fill_n(block.begin(), 33, uint8_t{0x42});
    SHA256(reinterpret_cast<const unsigned char*>(canonical.data()),
           canonical.size(),
           block.data() + 33);

    return bytes_to_hex_upper(rsa_sign(block));
}

// =============================================================================
// Binary patching
// =============================================================================

static bool patch(const fs::path& target)
{
    std::ifstream f(target, std::ios::binary);
    if (!f) {
        std::cout << "  Skip: " << target << " - didn't find\n";
        return false;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    f.close();

    if (std::search(data.begin(), data.end(),
                    PATCHED_MAGIC.begin(), PATCHED_MAGIC.end()) != data.end()) {
        std::cout << "  Already: " << target << " - patched modulus present\n";
        return false;
    }

    auto it = std::search(data.begin(), data.end(),
                          ORIGINAL_MAGIC.begin(), ORIGINAL_MAGIC.end());
    if (it == data.end()) {
        std::cout << "  Skip: " << target << " - doesn't contain original modulus\n";
        return false;
    }
    std::copy(PATCHED_MAGIC.begin(), PATCHED_MAGIC.end(), it);

    std::ofstream out(target, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    std::cout << "  OK: " << target << " - patched\n";
    return true;
}

// =============================================================================
// Install discovery  (mirrors find_ida_install_dirs in ida_keygen.py)
// =============================================================================

static fs::path normalize_install_dir(const fs::path& p)
{
#if defined(__APPLE__)
    if (p.extension() == ".app") return p / "Contents" / "MacOS";
#endif
    return p;
}

static void walk_strings(const rapidjson::Value& v, std::vector<std::string>& out)
{
    if (v.IsString())
        out.emplace_back(v.GetString(), v.GetStringLength());
    else if (v.IsObject())
        for (auto& m : v.GetObject()) walk_strings(m.value, out);
    else if (v.IsArray())
        for (auto& e : v.GetArray()) walk_strings(e, out);
}

// Read ida-config.json (in IDAUSR) and collect any string values that resolve
// to existing directories. Catches custom install paths from the installer.
static void collect_dirs_from_config(const fs::path& cfg, std::vector<fs::path>& out)
{
    std::ifstream f(cfg, std::ios::binary);
    if (!f) return;
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    rapidjson::Document d;
    if (d.Parse<rapidjson::kParseCommentsFlag>(content.c_str()).HasParseError())
        return;

    std::vector<std::string> strings;
    walk_strings(d, strings);

    std::error_code ec;
    for (const auto& s : strings)
        if (fs::is_directory(s, ec)) out.emplace_back(s);
}

static std::vector<fs::path> find_ida_install_dirs()
{
    std::vector<fs::path> dirs;
    std::error_code ec;

    dirs.emplace_back(".");
    if (const char* idadir = std::getenv("IDADIR"); idadir && *idadir)
        dirs.emplace_back(idadir);

    auto scan = [&](const fs::path& root, auto&& pred) {
        if (!fs::exists(root, ec)) return;
        for (const auto& e : fs::directory_iterator(root, ec)) {
            if (!e.is_directory(ec)) continue;
            if (pred(e.path().filename().string())) dirs.push_back(e.path());
        }
    };

#if defined(_WIN32)
    auto pred = [](const std::string& n) { return n.rfind("IDA", 0) == 0; };
    scan("C:/Program Files",       pred);
    scan("C:/Program Files (x86)", pred);
    if (const char* pf   = std::getenv("ProgramFiles"))      scan(pf,   pred);
    if (const char* pf86 = std::getenv("ProgramFiles(x86)")) scan(pf86, pred);
#elif defined(__APPLE__)
    scan("/Applications", [](const std::string& n) {
        return n.rfind("IDA", 0) == 0 && n.ends_with(".app");
    });
#else
    auto pred = [](const std::string& n) {
        return n.rfind("ida", 0) == 0 || n.rfind("IDA", 0) == 0;
    };
    scan("/opt", pred);
    if (const char* home = std::getenv("HOME")) scan(home, pred);
#endif

    if (const char* home = std::getenv("HOME"))
        collect_dirs_from_config(fs::path(home) / ".idapro" / "ida-config.json", dirs);
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"))
        collect_dirs_from_config(
            fs::path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json", dirs);
#endif

    std::vector<fs::path> out;
    std::vector<std::string> seen;
    for (const auto& d : dirs) {
        auto n = normalize_install_dir(d);
        const auto key = n.string();
        if (std::find(seen.begin(), seen.end(), key) == seen.end()) {
            seen.push_back(key);
            out.push_back(std::move(n));
        }
    }
    return out;
}

static const std::vector<std::string>& ida_lib_names()
{
    static const std::vector<std::string> names = {
#if defined(_WIN32)
        "ida.dll", "ida32.dll"
#elif defined(__APPLE__)
        "libida.dylib", "libida32.dylib"
#else
        "libida.so", "libida32.so"
#endif
    };
    return names;
}

// =============================================================================
// User-facing helpers
// =============================================================================

static const char* idadir_hint()
{
#if defined(_WIN32)
    return "  set IDADIR=C:\\Program Files\\IDA Professional 9.3";
#elif defined(__APPLE__)
    return "  export IDADIR=\"/Applications/IDA Professional 9.3.app/Contents/MacOS\"";
#else
    return "  export IDADIR=/opt/idapro-9.3";
#endif
}

static void wait_for_user()
{
#if defined(_WIN32)
    std::system("pause");
#else
    std::cout << "Press Enter to exit..." << std::flush;
    std::cin.get();
#endif
}

// =============================================================================
// Main
// =============================================================================

int main()
{
    auto loaded = load_license_template();
    if (!loaded) {
        std::cerr << loaded.error() << "\n";
        return 1;
    }
    auto& doc = *loaded;
    auto& allocator = doc.GetAllocator();

    add_every_decompiler(doc);

    const auto signature = sign_hexlic(doc["payload"]);
    doc.AddMember("signature",
                  rapidjson::Value(signature.c_str(), allocator),
                  allocator);

    {
        const auto serialized = canonical_json(doc);
        std::ofstream out(std::string(OUTPUT_FILENAME), std::ios::binary);
        out.write(serialized.data(),
                  static_cast<std::streamsize>(serialized.size()));
    }
    std::cout << "Saved new license to " << OUTPUT_FILENAME << "\n";

    std::cout << "\nDiscovering IDA installs...\n";
    bool any_patched = false;
    for (const auto& dir : find_ida_install_dirs())
        for (const auto& name : ida_lib_names())
            if (patch(dir / name)) any_patched = true;

    if (!any_patched) {
        std::cout << "\nNo IDA install with the original modulus was patched.\n"
                     "If your install is in a non-standard location, set IDADIR and re-run, e.g.:\n"
                  << idadir_hint() << "\n";
    }

#if defined(__APPLE__)
    std::cout << "\nOn macOS, re-sign the app after patching, e.g.:\n"
                 "  codesign --force --deep --sign - "
                 "\"/Applications/IDA Professional 9.3.app\"\n";
#endif

    wait_for_user();
    return 0;
}
