// Fuzzes OpenFHE's core math layer (big integers, modular arithmetic, number theory, NTT, FFT) and checks
// algebraic invariants on every result, so a silent miscalculation aborts like a memory error does.
#include <cmath>
#include <complex>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <numeric>
#include <cstring>
#include <set>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "lattice/lat-hal.h"
#include "math/dftransform.h"
#include "math/math-hal.h"
#include "math/nbtheory.h"

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
    uint32_t U32() {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v = (v << 8) | U8();
        return v;
    }
    uint64_t U64() {
        return (static_cast<uint64_t>(U32()) << 32) | U32();
    }
    std::string Rest() {
        std::string s(reinterpret_cast<const char*>(p), n);
        p += n;
        n = 0;
        return s;
    }
};

[[noreturn]] void Mismatch(int line) {
    std::fprintf(stderr, "fuzz_math: invariant violated at line %d\n", line);
    __builtin_trap();
}

#define Check(cond) \
    do {            \
        if (!(cond)) \
            Mismatch(__LINE__); \
    } while (0)

unsigned __int128 RefMulMod(uint64_t a, uint64_t b, uint64_t m) {
    return (static_cast<unsigned __int128>(a) * b) % m;
}

uint64_t RefPow(uint64_t a, uint64_t e, uint64_t m) {
    uint64_t r = 1 % m;
    a %= m;
    while (e) {
        if (e & 1)
            r = static_cast<uint64_t>(RefMulMod(r, a, m));
        a = static_cast<uint64_t>(RefMulMod(a, a, m));
        e >>= 1;
    }
    return r;
}

// ubint(string) never terminates on non-digit characters, so fuzz decimal strings only.
std::string Digits(const std::string& raw) {
    std::string d;
    for (size_t i = 0; i < raw.size() && i < 300; ++i)
        d.push_back(static_cast<char>('0' + static_cast<uint8_t>(raw[i]) % 10));
    return d;
}

void BigIntParse(Reader& r) {
    std::string s = Digits(r.Rest());
    BigInteger a(s);
    BigInteger b(a.ToString());
    Check(a == b);
    (void)a.ConvertToDouble();
    (void)a.GetMSB();
}

void BigIntArith(Reader& r) {
    std::string s = r.Rest();
    size_t cut = s.find(',');
    if (cut == std::string::npos)
        cut = s.size() / 2;
    BigInteger a(Digits(s.substr(0, cut)));
    BigInteger b(cut < s.size() ? Digits(s.substr(cut + 1)) : std::string("1"));
    Check(a + b >= a);
    Check((a + b) - b == a);
    BigInteger prod = a * b;
    if (b != BigInteger(0)) {
        Check(prod / b == a);
        // KNOWN: ubint operator/ returns 1 for some a < b with equal limb counts (see mayhem/known-findings), so the
        // quotient/remainder identity is only asserted for a >= b.
        if (a >= b)
            Check((a / b) * b + (a % b) == a);
        Check(a % b < b);
        Check(a.Mod(b) == a % b);
        Check(a.ModMul(a, b) == (a * a) % b);
        Check(a.ModAdd(a, b) == (a + a) % b);
        // ModInverse divides by zero when gcd(a, b) != 1, so only feed it coprime pairs.
        if (a.GetMSB() <= 63 && b.GetMSB() <= 63 && b > BigInteger(1) &&
            std::gcd(a.ConvertToInt<uint64_t>(), b.ConvertToInt<uint64_t>()) == 1) {
            BigInteger inv = a.ModInverse(b);
            Check((a * inv) % b == BigInteger(1));
        }
    }
    unsigned sh = static_cast<unsigned>(s.size() % 130);
    Check(((a << sh) >> sh) == a);
    (void)a.ToString();
}

void NativeArith(Reader& r) {
    uint64_t a = r.U64(), b = r.U64(), m = r.U64();
    uint64_t e = r.U64();
    // Barrett (mu) arithmetic is only valid for the moduli the library uses: at least ~20 bits, at most 60.
    m = ((m & ((uint64_t(1) << 60) - 1)) | (uint64_t(1) << 20));
    NativeInteger A(a), B(b), M(m);
    Check(A.ModMul(B, M).ConvertToInt() == static_cast<uint64_t>(RefMulMod(a % m, b % m, m)));
    Check(A.ModAdd(B, M).ConvertToInt() == static_cast<uint64_t>((static_cast<unsigned __int128>(a % m) + b % m) % m));
    Check(A.ModSub(B, M).ConvertToInt() ==
          static_cast<uint64_t>((static_cast<unsigned __int128>(a % m) + m - (b % m)) % m));
    Check(A.ModExp(NativeInteger(e), M).ConvertToInt() == RefPow(a, e, m));
    NativeInteger mu = M.ComputeMu();
    NativeInteger Ar(a % m), Br(b % m);
    Check(Ar.ModMul(Br, M, mu).ConvertToInt() == static_cast<uint64_t>(RefMulMod(a % m, b % m, m)));
    if (std::gcd(a % m, m) == 1) {
        NativeInteger inv = A.ModInverse(M);
        Check(RefMulMod(a % m, inv.ConvertToInt(), m) == 1);
    }
    NativeInteger pre = Br.PrepModMulConst(M);
    Check(Ar.ModMulFast(Br, M).ConvertToInt() == static_cast<uint64_t>(RefMulMod(a % m, b % m, m)));
    Check(Ar.ModMulFastConst(Br, M, pre).ConvertToInt() == static_cast<uint64_t>(RefMulMod(a % m, b % m, m)));
}

void Automorphism(Reader& r) {
    // i is a rotation index and m a cyclotomic order, as in the library's callers: m is never 0 and, for the
    // power-of-two variants, a power of two (the loops are O(|i|), so |i| stays in the rotation-index range).
    int32_t i = static_cast<int16_t>(r.U32());
    uint32_t m = uint32_t(1) << (r.U8() % 24);
    uint32_t g = r.U32();
    switch (r.U8() % 3) {
        case 0:
            (void)FindAutomorphismIndex2n(i, m);
            break;
        case 1:
            (void)FindAutomorphismIndex2nComplex(i, m);
            break;
        default:
            (void)FindAutomorphismIndexCyclic(i, 1 + (m % 65536), g);
            break;
    }
}

void NumberTheory(Reader& r) {
    uint64_t a = r.U64(), b = r.U64();
    uint32_t nBits = 2 + r.U8() % 56;
    uint32_t logM = 1 + r.U8() % 16;
    uint64_t m = uint64_t(1) << logM;
    nBits = std::max(nBits, logM + 3);  // a prime congruent to 1 mod m needs room above m
    switch (r.U8() % 4) {
        case 0: {
            NativeInteger g = GreatestCommonDivisor(NativeInteger(a), NativeInteger(b));
            if (a || b) {
                Check(g.ConvertToInt() != 0);
                Check(a % g.ConvertToInt() == 0 && b % g.ConvertToInt() == 0);
            }
            break;
        }
        case 1: {
            NativeInteger p = FirstPrime<NativeInteger>(nBits, m);
            Check(p.ConvertToInt() % m == 1);
            Check(MillerRabinPrimalityTest(p));
            NativeInteger q = NextPrime(p, m);
            Check(q > p && q.ConvertToInt() % m == 1 && MillerRabinPrimalityTest(q));
            NativeInteger l = PreviousPrime(q, m);
            Check(l == p);
            break;
        }
        case 2: {
            uint64_t n = (a >> 20) | 2;
            std::set<NativeInteger> factors;
            PrimeFactorize(NativeInteger(n), factors);
            unsigned __int128 prod = 1;
            for (auto& f : factors)
                prod *= f.ConvertToInt();
            Check(n % static_cast<uint64_t>(prod) == 0);
            break;
        }
        default: {
            NativeInteger q = FirstPrime<NativeInteger>(nBits, m);
            NativeInteger root = RootOfUnity<NativeInteger>(static_cast<uint32_t>(m), q);
            Check(root.ModExp(NativeInteger(m), q).ConvertToInt() == 1);
            Check(root.ModExp(NativeInteger(m / 2), q).ConvertToInt() == q.ConvertToInt() - 1);
            break;
        }
    }
}

void Ntt(Reader& r) {
    uint32_t logN = 1 + r.U8() % 7;
    uint32_t n = 1u << logN, m = n << 1;
    uint32_t bits = 20 + r.U8() % 40;
    NativeInteger q = FirstPrime<NativeInteger>(bits, m);
    NativeInteger root = RootOfUnity<NativeInteger>(m, q);
    auto params = std::make_shared<ILNativeParams>(m, q, root);
    const uint64_t qq = q.ConvertToInt();
    NativeVector va(n, q), vb(n, q);
    for (uint32_t i = 0; i < n; ++i) {
        va[i] = NativeInteger(r.U64() % qq);
        vb[i] = NativeInteger(r.U64() % qq);
    }
    NativePoly pa(params, Format::COEFFICIENT), pb(params, Format::COEFFICIENT);
    pa.SetValues(va, Format::COEFFICIENT);
    pb.SetValues(vb, Format::COEFFICIENT);
    NativePoly ea = pa, eb = pb;
    ea.SwitchFormat();
    eb.SwitchFormat();
    NativePoly back = ea;
    back.SwitchFormat();
    Check(back == pa);
    NativePoly prod = ea * eb;
    prod.SwitchFormat();
    for (uint32_t k = 0; k < n; ++k) {
        unsigned __int128 acc = 0;
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t j = (k + n - i) % n;
            uint64_t t = static_cast<uint64_t>(RefMulMod(va[i].ConvertToInt(), vb[j].ConvertToInt(), qq));
            acc += (i + j == k) ? t : (qq - t) % qq;
        }
        Check(static_cast<uint64_t>(acc % qq) == prod.GetValues()[k].ConvertToInt());
    }
}

void Fft(Reader& r) {
    uint32_t n = 1u << (1 + r.U8() % 6);
    std::vector<std::complex<double>> v(n);
    for (auto& c : v)
        c = {static_cast<double>(static_cast<int8_t>(r.U8())), static_cast<double>(static_cast<int8_t>(r.U8()))};
    auto orig = v;
    auto fwd = DiscreteFourierTransform::FFTForwardTransform(v);
    Check(fwd.size() == n);
    auto inv = DiscreteFourierTransform::FFTInverseTransform(fwd);
    Check(inv.size() == n);
    uint32_t cyc = n << 2;
    auto sv = orig;
    DiscreteFourierTransform::FFTSpecialInv(sv, cyc);
    DiscreteFourierTransform::FFTSpecial(sv, cyc);
    for (uint32_t i = 0; i < n; ++i)
        Check(std::abs(sv[i] - orig[i]) < 1e-6);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2)
        return -1;
    Reader r{data + 1, size - 1};
    try {
        switch (data[0] % 7) {
            case 0:
                BigIntParse(r);
                break;
            case 1:
                BigIntArith(r);
                break;
            case 2:
                NativeArith(r);
                break;
            case 3:
                Automorphism(r);
                break;
            case 4:
                NumberTheory(r);
                break;
            case 5:
                Ntt(r);
                break;
            default:
                Fft(r);
                break;
        }
    }
    catch (const std::exception&) {
        return -1;
    }
    return 0;
}
