// Dev tool: writes the starter seed corpus for fuzz_deser_{binary,json}. Seed = <kind byte> + serialized object.
// Usage: gen_seeds <binary|json> <outdir>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "fixture.h"

using namespace lbcrypto;

static std::string g_dir;
static bool g_json = false;

template <typename T>
static std::string Ser(const T& obj) {
    std::ostringstream os;
    if (g_json)
        Serial::Serialize(obj, os, SerType::JSON);
    else
        Serial::Serialize(obj, os, SerType::BINARY);
    return os.str();
}

static void Put(int kind, const std::string& name, const std::string& payload) {
    std::ofstream f(g_dir + "/seed_" + std::to_string(kind) + "_" + name, std::ios::binary);
    f.put(static_cast<char>(kind));
    f << payload;
}

template <typename P>
static void OtherSchemeSeeds(const std::string& name, P& p, bool ckks) {
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto kp = cc->KeyGen();
    Plaintext pt = ckks ? cc->MakeCKKSPackedPlaintext(std::vector<double>{1.0, 2.0, 3.0}) :
                          cc->MakePackedPlaintext(std::vector<int64_t>{1, 2, 3});
    Put(0, name + "_ct", Ser(cc->Encrypt(kp.publicKey, pt)));
    Put(4, name + "_cc", Ser(cc));
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: gen_seeds <binary|json> <outdir>\n";
        return 2;
    }
    g_json = std::string(argv[1]) == "json";
    g_dir = argv[2];

    auto fx = mayhem::MakeBgvFixture();
    Put(0, "bgv_ct", Ser(fx.ct));
    Put(1, "bgv_ct", Ser(fx.ct));
    Put(2, "bgv_pk", Ser(fx.kp.publicKey));
    Put(3, "bgv_sk", Ser(fx.kp.secretKey));
    Put(4, "bgv_cc", Ser(fx.cc));
    {
        std::ostringstream os;
        if (g_json)
            CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(os, SerType::JSON, mayhem::kKeyTag);
        else
            CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(os, SerType::BINARY, mayhem::kKeyTag);
        Put(5, "bgv_evalmult", os.str());
    }
    {
        std::ostringstream os;
        if (g_json)
            CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(os, SerType::JSON, mayhem::kKeyTag);
        else
            CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(os, SerType::BINARY, mayhem::kKeyTag);
        Put(6, "bgv_evalrot", os.str());
    }

    {
        CCParams<CryptoContextBFVRNS> p;
        p.SetPlaintextModulus(65537);
        p.SetMultiplicativeDepth(1);
        p.SetRingDim(32);
        p.SetSecurityLevel(HEStd_NotSet);
        OtherSchemeSeeds("bfv", p, false);
    }
    {
        CCParams<CryptoContextCKKSRNS> p;
        p.SetMultiplicativeDepth(1);
        p.SetScalingModSize(40);
        p.SetRingDim(32);
        p.SetBatchSize(4);
        p.SetSecurityLevel(HEStd_NotSet);
        OtherSchemeSeeds("ckks", p, true);
    }
    return 0;
}
