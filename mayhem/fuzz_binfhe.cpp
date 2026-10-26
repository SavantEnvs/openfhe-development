// Fuzzes OpenFHE's FHEW/TFHE-style boolean gates (BinFHE, TOY parameters): a chain of bootstrapped gates whose
// decrypted outputs must match the plaintext truth table. Any mismatch traps.
#include <cstdint>
#include <cstdio>
#include <vector>

#include "binfhecontext.h"

using namespace lbcrypto;

namespace {

struct Ctx {
    BinFHEContext cc;
    LWEPrivateKey sk;
};

std::vector<Ctx>* g_ctx = nullptr;

bool Ref(BINGATE g, int a, int b) {
    switch (g) {
        case AND:
            return a & b;
        case OR:
            return a | b;
        case NAND:
            return !(a & b);
        case NOR:
            return !(a | b);
        case XOR:
            return a ^ b;
        default:
            return !(a ^ b);
    }
}

[[noreturn]] void Mismatch() {
    std::fprintf(stderr, "fuzz_binfhe: gate output differs from the truth table\n");
    __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    g_ctx = new std::vector<Ctx>();
    for (BINFHE_METHOD m : {GINX, AP}) {
        Ctx c;
        c.cc.GenerateBinFHEContext(TOY, m);
        c.sk = c.cc.KeyGen();
        c.cc.BTKeyGen(c.sk);
        g_ctx->push_back(std::move(c));
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3)
        return -1;
    Ctx& c = (*g_ctx)[data[0] & 1];
    static const BINGATE gates[] = {AND, OR, NAND, NOR, XOR, XNOR};
    int val = data[1] & 1;
    LWECiphertext acc = c.cc.Encrypt(c.sk, val);
    size_t ops = 0;
    for (size_t i = 2; i + 1 < size && ops < 4; i += 2, ++ops) {
        int b = data[i + 1] & 1;
        if (data[i] % 7 == 6) {
            acc = c.cc.EvalNOT(acc);
            val = !val;
        }
        else {
            BINGATE g = gates[data[i] % 6];
            acc = c.cc.EvalBinGate(g, acc, c.cc.Encrypt(c.sk, b));
            val = Ref(g, val, b);
        }
        LWEPlaintext out;
        c.cc.Decrypt(c.sk, acc, &out);
        if (out != val)
            Mismatch();
    }
    return 0;
}
