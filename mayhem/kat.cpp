// Known-answer probe for mayhem/test.sh. Built with the project's normal flags (no sanitizers, no fuzzer
// instrumentation) and dynamically linked, so the sabotage shim can neuter it. Prints one value per line;
// test.sh compares every line against exact expected output.
#include <iostream>
#include <vector>

#include "binfhecontext.h"
#include "fixture.h"

using namespace lbcrypto;

static void PrintSlots(const std::string& label, const std::vector<int64_t>& v) {
    std::cout << label;
    for (size_t i = 0; i < 4; ++i)
        std::cout << ' ' << v[i];
    std::cout << '\n';
}

int main() {
    // Arithmetic on the integer types.
    BigInteger a("123456789012345678901234567890"), b("987654321098765432109876543210");
    std::cout << "bigint mul " << (a * b).ToString() << '\n';
    std::cout << "bigint modmul " << (a * b % BigInteger(1000000007)).ToString() << '\n';
    std::cout << "bigint div " << (b / a).ToString() << " rem " << (b % a).ToString() << '\n';
    NativeInteger three(3), q(1000003);
    std::cout << "native modexp " << three.ModExp(NativeInteger(200), q) << '\n';
    std::cout << "native modinv " << NativeInteger(123456789).ModInverse(NativeInteger(1000000007)) << '\n';
    std::cout << "gcd " << GreatestCommonDivisor(NativeInteger(1870269278846976ULL), NativeInteger(1859832508317696ULL)) << '\n';

    // BGV: exact integer arithmetic under encryption.
    auto fx = mayhem::MakeBgvFixture();
    auto cc = fx.cc;
    auto ca = cc->Encrypt(fx.kp.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>{1, 2, 3, 4}));
    auto cb = cc->Encrypt(fx.kp.publicKey, cc->MakePackedPlaintext(std::vector<int64_t>{5, 6, 7, 8}));
    Plaintext out;
    cc->Decrypt(fx.kp.secretKey, cc->EvalAdd(ca, cb), &out);
    out->SetLength(4);
    PrintSlots("bgv add", out->GetPackedValue());
    cc->Decrypt(fx.kp.secretKey, cc->EvalMult(ca, cb), &out);
    out->SetLength(4);
    PrintSlots("bgv mult", out->GetPackedValue());
    cc->Decrypt(fx.kp.secretKey, cc->EvalSub(cb, ca), &out);
    out->SetLength(4);
    PrintSlots("bgv sub", out->GetPackedValue());

    // BinFHE: bootstrapped gate truth tables (inputs 00 01 10 11).
    BinFHEContext bc;
    bc.GenerateBinFHEContext(TOY, GINX);
    auto sk = bc.KeyGen();
    bc.BTKeyGen(sk);
    const struct {
        const char* name;
        BINGATE gate;
    } gates[] = {{"and", AND}, {"or", OR}, {"xor", XOR}, {"nand", NAND}};
    for (const auto& g : gates) {
        std::cout << "binfhe " << g.name << ' ';
        for (int x = 0; x < 2; ++x)
            for (int y = 0; y < 2; ++y) {
                LWEPlaintext r;
                bc.Decrypt(sk, bc.EvalBinGate(g.gate, bc.Encrypt(sk, x), bc.Encrypt(sk, y)), &r);
                std::cout << r;
            }
        std::cout << '\n';
    }
    return 0;
}
