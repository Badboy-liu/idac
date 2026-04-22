#include <algorithm>
#include <iostream>
#include "rapidjson/document.h"    // 用于解析 (DOM)
#include "rapidjson/writer.h"      // 用于生成 JSON
#include "rapidjson/stringbuffer.h"
#include "rapidjson/filereadstream.h" // 用于文件流读取
#include <iostream>
#include <fstream>
#include <filesystem>
#include <expected>
#include <format>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <map>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <fstream> // 必须包含这个头文件

std::expected<rapidjson::Document,int> load_json(const char*  json_path);
void add_every_addon(rapidjson::Document& d);
std::string  sign_hexlic(
    const std::string& json_data);
// 1) json_stringify_alphabetical: sort_keys=True + separators=(",", ":")
static void WriteValueSorted(const rapidjson::Value& v,
                             rapidjson::Writer<rapidjson::StringBuffer>& w);
std::string bytes_to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> bigint_to_buf(const BIGNUM* bn);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
BIGNUM* little_endian_to_bn(const std::string& hex);
typedef boost::multiprecision::cpp_int bigint;
BIGNUM* pub_modulus_hexrays = little_endian_to_bn(
"edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
);

BIGNUM* pub_modulus_patched = little_endian_to_bn(
"edfd42cbf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
);

BIGNUM* private_key = little_endian_to_bn(
"77c86abbb7f3bb134436797b68ff47beb1a5457816608dbfb72641814dd464dd640d711d5732d3017a1c4e63d835822f00a4eab619a2c4791cf33f9f57f9c2ae4d9eed9981e79ac9b8f8a411f68f25b9f0c05d04d11e22a3a0d8d4672b56a61f1532282ff4e4e74759e832b70e98b9d102d07e9fb9ba8d15810b144970029874"
);
// std::vector<unsigned char> hex_to_bytes(const std::string& hex)
// {
//     std::vector<unsigned char> bytes;
//     bytes.reserve(hex.length() / 2);
//
//     for (size_t i = 0; i < hex.length(); i += 2)
//     {
//         std::string byteString = hex.substr(i, 2);
//         unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
//         bytes.push_back(byte);
//     }
//
//     return bytes;
// }
BIGNUM* little_endian_to_bn(const std::string& hex)
{
    auto bytes = hex_to_bytes(hex);

    std::reverse(bytes.begin(), bytes.end());  // 关键！

    return BN_bin2bn(bytes.data(), bytes.size(), nullptr);
}


std::vector<uint8_t> hex_to_bytes(const std::string& hex)
{
    std::vector<uint8_t> bytes;

    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}


BIGNUM* buf_to_bigint(const std::vector<uint8_t>& buf)
{
    std::vector<uint8_t> tmp(buf);

    // little endian -> big endian
    std::reverse(tmp.begin(), tmp.end());

    return BN_bin2bn(tmp.data(), tmp.size(), nullptr);
}



std::vector<uint8_t> rsa_pow(
    const std::vector<uint8_t>& message,
    const BIGNUM* exponent,
    const BIGNUM* modulus)
{
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* m = buf_to_bigint(message);
    BIGNUM* r = BN_new();

    BN_mod_exp(r, m, exponent, modulus, ctx);

    auto out = bigint_to_buf(r);

    BN_free(m);
    BN_free(r);
    BN_CTX_free(ctx);

    return out;
}



std::string bytes_to_hex(const std::vector<uint8_t>& data)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;

    for (uint8_t b : data)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }

    return out;
}
// BIGNUM* buf_to_bigint(const std::vector<uint8_t>& buf)
// {
//     BIGNUM* bn = BN_new();
//
//     BN_bin2bn(buf.data(), buf.size(), bn);
//
//     return bn;
// }


std::vector<uint8_t> bigint_to_buf(const BIGNUM* bn)
{
    int len = BN_num_bytes(bn);

    std::vector<uint8_t> buf(len);

    BN_bn2bin(bn, buf.data());

    // big -> little
    std::reverse(buf.begin(), buf.end());

    return buf;
}

std::vector<uint8_t> encrypt(
    std::vector<uint8_t> message,
    const BIGNUM* private_key,
    const BIGNUM* modulus)
{
    std::reverse(message.begin(), message.end());

    auto encrypted = rsa_pow(message, private_key, modulus);

    return encrypted;
}
std::vector<uint8_t> decrypt(
    const std::vector<uint8_t>& message,
    const BIGNUM* exponent,
    const BIGNUM* modulus)
{
    auto decrypted = rsa_pow(message, exponent, modulus);

    std::reverse(decrypted.begin(), decrypted.end());

    return decrypted;
}
std::string sign_hexlic(const std::string& json_data)
{

    std::vector<uint8_t> buffer(128, 0);

    for (int i = 0; i < 33; i++)
        buffer[i] = 0x42;

    uint8_t hash[SHA256_DIGEST_LENGTH];

    SHA256(
        reinterpret_cast<const unsigned char*>(json_data.data()),
        json_data.size(),
        hash
    );
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        std::cout<<std::format("{:02x}", hash[i]);
    }
    std::printf("\n");

    for (int i = 0; i < 32; i++)
        buffer[33 + i] = hash[i];

    auto encrypted = encrypt(buffer, private_key, pub_modulus_patched);
    for (int i = 0; i < encrypted.size(); i++)
    {
        std::cout<<std::format("{:02x}", encrypted[i]);
    }
    std::printf("\n");
    return bytes_to_hex(encrypted);
}
void patch(const std::string& filename)
{
    std::ifstream f(filename, std::ios::binary);

    if (!f)
    {
        std::cout << "Skip: " << filename << " - didn't find\n";
        return;
    }

    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>()
    );

    auto original = hex_to_bytes("EDFD425CF978");
    auto patched  = hex_to_bytes("EDFD42CBF978");

    auto it = std::search(data.begin(), data.end(), original.begin(), original.end());

    if (it == data.end())
    {
        std::cout << "Patch: " << filename << " - doesn't contain original modulus\n";
        return;
    }

    std::copy(patched.begin(), patched.end(), it);

    std::ofstream out(filename, std::ios::binary);
    out.write((char*)data.data(), data.size());

    std::cout << "Patch: " << filename << " - OK\n";
}

std::string json_stringify_alphabetical(const rapidjson::Document& doc)
{
    std::map<std::string, const rapidjson::Value*> sorted;

    for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it)
    {
        sorted[it->name.GetString()] = &it->value;
    }

    rapidjson::Document out;
    out.SetObject();
    auto& allocator = out.GetAllocator();

    for (auto& kv : sorted)
    {
        rapidjson::Value key(kv.first.c_str(), allocator);
        rapidjson::Value val;
        val.CopyFrom(*kv.second, allocator);

        out.AddMember(key, val, allocator);
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    out.Accept(writer);

    return buffer.GetString();
}


void add_every_addon(rapidjson::Document& d)
{
    // auto addons = d["addons"].GetArray();
    std::vector<std::string> addons = {
        "HEXX86",
        "HEXX64",
        "HEXARM",
        "HEXARM64",
        "HEXMIPS",
        "HEXMIPS64",
        "HEXPPC",
        "HEXPPC64",
        "HEXRV64",
        "HEXARC",
        "HEXARC64"
    };
    rapidjson::Value arr(rapidjson::kArrayType);
    auto& allocator = d.GetAllocator();

    auto add_ons = d["payload"]["licenses"][0]["add_ons"].GetArray();
    int i = 0;
    for (auto& value : addons)
    {
        i += 1;
        rapidjson::Value obj(rapidjson::kObjectType);
        std::string id =d["payload"]["licenses"][0]["id"].GetString();

        obj.AddMember("id", rapidjson::Value(std::format("48-1337-0000-{:02}", i).c_str(),allocator), allocator);
        obj.AddMember("code", rapidjson::Value(value.c_str(),allocator), allocator);
        obj.AddMember("owner", rapidjson::Value(id.c_str(),allocator), allocator);
        obj.AddMember("start_date", rapidjson::Value("2024-08-10 00:00:00"), allocator);
        obj.AddMember("end_date", rapidjson::Value("2083-12-31 23:59:59"), allocator);
        add_ons.PushBack(obj, allocator);
    }
}

#include <iostream>
#include <map>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

using namespace rapidjson;

void sort_json(const Value& src, Value& dst, Document::AllocatorType& allocator)
{
    if (src.IsObject())
    {
        dst.SetObject();

        std::map<std::string, const Value*> sorted;

        for (auto it = src.MemberBegin(); it != src.MemberEnd(); ++it)
        {
            sorted[it->name.GetString()] = &it->value;
        }

        for (auto& kv : sorted)
        {
            Value key(kv.first.c_str(), allocator);

            Value value;
            sort_json(*kv.second, value, allocator);

            dst.AddMember(key, value, allocator);
        }
    }
    else if (src.IsArray())
    {
        dst.SetArray();

        for (auto& v : src.GetArray())
        {
            Value value;
            sort_json(v, value, allocator);

            dst.PushBack(value, allocator);
        }
    }
    else
    {
        dst.CopyFrom(src, allocator);
    }
}

std::string json_stringify_alphabetical(const rapidjson::Value& doc)
{
    rapidjson::Document sorted;
    sorted.CopyFrom(doc, sorted.GetAllocator());

    auto& allocator = sorted.GetAllocator();

    rapidjson::Value result;
    sort_json(sorted, result, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    result.Accept(writer);
    // std::cout<<"buffer"<<buffer.GetString()<<std::endl;
    auto np = "{\"payload\":"+std::string(buffer.GetString())+"}";
    std::cout<<"buffer"<<np<<std::endl;

    return np;
}

static std::string json = R"(
{
  "header": {"version": 1},
  "payload": {
      "name": "HuanmengX",
      "email": "idapro9@example.com",
      "licenses": [
        {
          "id": "48-2137-ACAB-99",
          "edition_id": "ida-pro",
          "description": "license",
          "license_type": "named",
          "product": "IDA",
          "product_id": "IDAPRO",
          "product_version": "9.3",
          "seats": 1,
          "start_date": "2024-08-10 00:00:00",
          "end_date": "2083-12-31 23:59:59",
          "issued_on": "2024-08-10 00:00:00",
          "owner": "Creaked By HuanmengX@outlook.com",
          "add_ons": [],
          "features": []
        }
      ]
    }
}
)";
std::expected<rapidjson::Document,int> load_json(const char*  json_path)
{
    // auto fp = fopen(json_path,"rb");
    // if (!fp) {
    //     std::cerr << "无法打开文件!" << std::endl;
    //     return std::unexpected(-1);
    // }
    // rapidjson::Document doc;
    // fseek(fp, 0, SEEK_END);
    // size_t fileSize = ftell(fp);
    // rewind(fp);
    // char* buffer = new char[fileSize + 1];
    // fread(buffer, 1, fileSize, fp);
    // buffer[fileSize] = '\0'; // 确保字符串以 null 结尾
    // fclose(fp);


    // 3. 解析 JSON
    rapidjson::Document d;
    // kParseCommentsFlag 允许解析带注释的 JSON (非标准但常用)
    if (d.Parse<rapidjson::kParseCommentsFlag>(json.c_str()).HasParseError()) {
        std::cerr << "解析错误 at offset " << d.GetErrorOffset()
             << ": " << rapidjson::GetParseErrorFunc(d.GetParseError()) << std::endl;
        // delete[] buffer;
        return std::unexpected(-1);
    }

    auto s = d["payload"]["licenses"][0]["id"].GetString();

    std::cout<<s<<std::endl;

    return d;
}


int main()
{
    auto d = load_json("../licenses.json");
    if (!d.has_value())
    {
        std::cout << "解析licenses.json错误" << std::endl;
    }

    add_every_addon(d.value());
    auto& allocator = d.value().GetAllocator();

    rapidjson::Value signature(sign_hexlic(json_stringify_alphabetical(d.value()["payload"])).c_str(),allocator);

    d.value().AddMember("signature",signature,allocator);
    auto d_json = json_stringify_alphabetical(d.value());

    std::string path ="idapro.hexlic";
    // scanf_s(path.c_str());
    // path+="idapro.hexlic";
    // auto file = fopen(path.c_str(),"rbw");
    std::ofstream outFile(path,std::ios::binary);

    if (!outFile.is_open())
    {
        std::cout<<"找不到idapro.hexlic"<<std::endl;
    }
    outFile.write(d_json.c_str(),d_json.size());
    outFile.close();
    std::cout<<"Saved new license to idapro.hexlic"<<std::endl;
    patch("ida.dll");
    patch("ida32.dll");
    system("pause");
    return 0;
}