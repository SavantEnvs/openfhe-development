// Fuzzes CryptoContext parameter validation and the encrypt/add/mult/decrypt path across BGV, BFV and CKKS:
// fuzzed parameters either get rejected with an exception or yield a context whose arithmetic is correct.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

namespace {

struct Reader {
    const uint8_t* p;
    size_t n;
    uint8_t U8() {
        if (n == 0)
            return 0;
        --n;
        return *p++;
    }
};

[[noreturn]] void Mismatch(const char* what) {
    std::fprintf(stderr, "fuzz_params: wrong result: %s\n", what);
    __builtin_trap();
}

template <typename P>
void Common(P& p, Reader& r, bool allowZeroDepth, bool manualScaling) {
    p.SetSecurityLevel(HEStd_NotSet);
    p.SetRingDim(uint32_t(16) << (r.U8() % 3));
    p.SetMultiplicativeDepth((r.U8() % 3) + (allowZeroDepth ? 0 : 1));
    p.SetScalingTechnique(manualScaling && r.U8() % 2 ? FIXEDMANUAL : FLEXIBLEAUTO);
}

template <typename P>
void Exercise(P& p, bool ckks, int64_t pmod) {
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    if (ckks) {
        std::vector<double> a{1.5, -2.25, 3.0, 0.5}, b{0.5, 4.0, -1.0, 2.0};
        auto ca = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(a));
        auto cb = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(b));
        Plaintext out;
        cc->Decrypt(kp.secretKey, cc->EvalAdd(ca, cb), &out);
        out->SetLength(4);
        for (size_t i = 0; i < 4; ++i)
            if (std::abs(out->GetCKKSPackedValue()[i].real() - (a[i] + b[i])) > 1e-2)
                Mismatch("ckks add");
        cc->Decrypt(kp.secretKey, cc->EvalMult(ca, cb), &out);
        out->SetLength(4);
        for (size_t i = 0; i < 4; ++i)
            if (std::abs(out->GetCKKSPackedValue()[i].real() - a[i] * b[i]) > 1e-1) {
                std::fprintf(stderr, "slot %zu: got %g want %g\n", i, out->GetCKKSPackedValue()[i].real(), a[i] * b[i]);
                Mismatch("ckks mult");
            }
    }
    else {
        std::vector<int64_t> a{1, 2, 3, 4}, b{5, 6, 7, 8};
        auto ca = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(a));
        auto cb = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(b));
        Plaintext out;
        cc->Decrypt(kp.secretKey, cc->EvalAdd(ca, cb), &out);
        out->SetLength(4);
        for (size_t i = 0; i < 4; ++i)
            if (out->GetPackedValue()[i] != (a[i] + b[i]) % pmod)
                Mismatch("integer add");
        cc->Decrypt(kp.secretKey, cc->EvalMult(ca, cb), &out);
        out->SetLength(4);
        for (size_t i = 0; i < 4; ++i)
            if (out->GetPackedValue()[i] != (a[i] * b[i]) % pmod)
                Mismatch("integer mult");
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2)
        return -1;
    Reader r{data + 1, size - 1};
    // 65537 and 786433 are primes congruent to 1 mod 2*ringDim for every ring dimension used here.
    const int64_t pmods[] = {65537, 786433};
    try {
        switch (data[0] % 3) {
            case 0: {
                CCParams<CryptoContextBGVRNS> p;
                int64_t pm = pmods[r.U8() % 2];
                p.SetPlaintextModulus(pm);
                Common(p, r, false, true);
                p.SetScalingModSize(20 + r.U8() % 20);
                Exercise(p, false, pm);
                break;
            }
            case 1: {
                CCParams<CryptoContextBFVRNS> p;
                int64_t pm = pmods[r.U8() % 2];
                p.SetPlaintextModulus(pm);
                Common(p, r, false, true);
                p.SetScalingModSize(20 + r.U8() % 20);
                Exercise(p, false, pm);
                break;
            }
            default: {
                CCParams<CryptoContextCKKSRNS> p;
                Common(p, r, false, false);
                p.SetScalingModSize(40 + r.U8() % 11);
                p.SetFirstModSize(60);
                Exercise(p, true, 0);
                break;
            }
        }
    }
    catch (const std::exception&) {
        return -1;
    }
    return 0;
}
