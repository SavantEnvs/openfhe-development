#pragma once
// Shared, deterministic OpenFHE fixture for the Mayhem harnesses, the seed generator and the KAT probe.
#include <string>
#include <vector>

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace mayhem {

using namespace lbcrypto;

// Fixed key tag so that serialized evaluation keys in the seed corpus name the key the harness really holds.
inline const char* kKeyTag = "0123456789abcdef0123456789abcdef";

struct BgvFixture {
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp;
    Ciphertext<DCRTPoly> ct;
};

inline void GenEvalKeys(BgvFixture& f) {
    f.cc->EvalMultKeyGen(f.kp.secretKey);
    f.cc->EvalRotateKeyGen(f.kp.secretKey, {1, -1});
}

inline BgvFixture MakeBgvFixture() {
    CCParams<CryptoContextBGVRNS> p;
    p.SetPlaintextModulus(65537);
    p.SetMultiplicativeDepth(1);
    p.SetRingDim(32);
    p.SetSecurityLevel(HEStd_NotSet);
    BgvFixture f;
    f.cc = GenCryptoContext(p);
    f.cc->Enable(PKE);
    f.cc->Enable(KEYSWITCH);
    f.cc->Enable(LEVELEDSHE);
    f.kp = f.cc->KeyGen();
    f.kp.secretKey->SetKeyTag(kKeyTag);
    f.kp.publicKey->SetKeyTag(kKeyTag);
    GenEvalKeys(f);
    f.ct = f.cc->Encrypt(f.kp.publicKey, f.cc->MakePackedPlaintext(std::vector<int64_t>{1, 2, 3, 4}));
    return f;
}

}  // namespace mayhem
