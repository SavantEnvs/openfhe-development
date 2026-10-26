// Fuzzes OpenFHE's cereal deserialization of crypto contexts, ciphertexts, keys and evaluation keys,
// then uses whatever came out of the parser (decrypt / add / multiply / rotate / encrypt).
// Compiled twice: -DMAYHEM_SER_BINARY (SerType::BINARY) and -DMAYHEM_SER_JSON (SerType::JSON).
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <memory>
#include <sstream>
#include <new>
#include <string>

#include "fixture.h"

#if defined(MAYHEM_SER_JSON)
#define MAYHEM_SERTYPE SerType::JSON
#else
#define MAYHEM_SERTYPE SerType::BINARY
#endif

using namespace lbcrypto;

// cereal's binary archives trust every length prefix and resize containers to it, so one root cause is
// reported once per container call site. Allocations above this cap fail with std::bad_alloc, which the
// harness catches like any other parse error (mayhem/known-findings/README.md).
static constexpr size_t kMaxAlloc = size_t(256) << 20;

void* operator new(size_t n) {
    if (n > kMaxAlloc)
        throw std::bad_alloc();
    if (void* p = std::malloc(n ? n : 1))
        return p;
    throw std::bad_alloc();
}
void* operator new[](size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }
void operator delete[](void* p, size_t) noexcept { std::free(p); }

static std::unique_ptr<mayhem::BgvFixture> g_fx;

struct Registry : CryptoContextFactory<DCRTPoly> {
    static void Reset(const CryptoContext<DCRTPoly>& keep) {
        ReleaseAllContexts();
        AddContext(keep);
    }
};

// The library never checks that a ciphertext belongs to the context it is decrypted/evaluated with
// (see mayhem/fuzz_deser_binary/known-findings), so, like an embedder, only operate on our own context's objects.
template <typename T>
static bool Owned(const T& obj) {
    return obj && obj->GetCryptoContext() == g_fx->cc;
}

static void ResetRegistry() {
    Registry::Reset(g_fx->cc);
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    g_fx = std::make_unique<mayhem::BgvFixture>(mayhem::MakeBgvFixture());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2)
        return -1;
    const uint8_t kind = data[0] % 7;
    std::istringstream in(std::string(reinterpret_cast<const char*>(data + 1), size - 1));
    bool ok = false;
    try {
        auto& cc = g_fx->cc;
        const std::vector<int64_t> v{5, 6, 7};
        switch (kind) {
            case 0: {
                Ciphertext<DCRTPoly> ct;
                Serial::Deserialize(ct, in, MAYHEM_SERTYPE);
                if (!Owned(ct))
                    break;
                Plaintext pt;
                cc->Decrypt(g_fx->kp.secretKey, ct, &pt);
                auto sum = cc->EvalAdd(ct, g_fx->ct);
                cc->Decrypt(g_fx->kp.secretKey, sum, &pt);
                ok = true;
                break;
            }
            case 1: {
                mayhem::GenEvalKeys(*g_fx);
                Ciphertext<DCRTPoly> ct;
                Serial::Deserialize(ct, in, MAYHEM_SERTYPE);
                if (!Owned(ct))
                    break;
                auto prod = cc->EvalMult(ct, g_fx->ct);
                Plaintext pt;
                cc->Decrypt(g_fx->kp.secretKey, prod, &pt);
                ok = true;
                break;
            }
            case 2: {
                PublicKey<DCRTPoly> pk;
                Serial::Deserialize(pk, in, MAYHEM_SERTYPE);
                if (!Owned(pk))
                    break;
                auto ct = cc->Encrypt(pk, cc->MakePackedPlaintext(v));
                ok = true;
                break;
            }
            case 3: {
                PrivateKey<DCRTPoly> sk;
                Serial::Deserialize(sk, in, MAYHEM_SERTYPE);
                if (!Owned(sk))
                    break;
                Plaintext pt;
                cc->Decrypt(sk, g_fx->ct, &pt);
                ok = true;
                break;
            }
            case 4: {
                CryptoContext<DCRTPoly> other;
                Serial::Deserialize(other, in, MAYHEM_SERTYPE);
                if (other)
                    (void)other->GetRingDimension();
                ok = true;
                break;
            }
            case 5: {
                ResetRegistry();
                mayhem::GenEvalKeys(*g_fx);
                CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(in, MAYHEM_SERTYPE);
                auto prod = cc->EvalMult(g_fx->ct, g_fx->ct);
                Plaintext pt;
                cc->Decrypt(g_fx->kp.secretKey, prod, &pt);
                ok = true;
                break;
            }
            case 6: {
                ResetRegistry();
                mayhem::GenEvalKeys(*g_fx);
                CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey(in, MAYHEM_SERTYPE);
                auto rot = cc->EvalRotate(g_fx->ct, 1);
                Plaintext pt;
                cc->Decrypt(g_fx->kp.secretKey, rot, &pt);
                ok = true;
                break;
            }
        }
    }
    catch (const std::exception&) {
    }
    ResetRegistry();
    return ok ? 0 : -1;
}
