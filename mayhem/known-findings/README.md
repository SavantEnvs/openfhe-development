# Known library defects found while writing the harnesses

The harnesses keep inputs inside each API's documented contract so that Mayhem spends its time on new
defects. Each bound below was added after the fuzzer (or a seed) hit a real library defect.

- `bfv_ciphertext_decrypted_with_bgv_context.bin` — feed to `fuzz_deser_binary` with the `Owned()` guard in
  `fuzz_deser.cpp` removed. A BFV ciphertext deserialized into a BGV context crashes `Decrypt` with a null
  dereference at `bgvrns-pke.cpp:61` (`dynamic_pointer_cast` to the BGV parameters returns null); the library
  never checks that a ciphertext belongs to the context it is used with.
- Allocation class: cereal binary archives trust every container length prefix and `resize()` to it, so a
  few input bytes request terabytes. Mayhem reports "Memory Allocation with Excessive Size Value" once per
  container call site (8 of the 15 defects in the first `fuzz_deser_binary` run), all one root cause. The
  deserialization harness replaces `operator new` to throw `std::bad_alloc` above 256 MiB, which it
  catches, so the class stays out of the defect list.
- `PublicKey`/`PrivateKey` deserialized from another context crash `Encrypt` (`dcrtpoly.h:405`, null
  dereference) and `Decrypt` the same way as the ciphertext case above, so cases 2 and 3 apply the same
  `Owned()` guard.
- `bigint_division_a_lt_b.cpp` — `BigInteger` (MATHBACKEND 4) `a / b` returns 1 for
  a = 5555555555400055555555 < b = 5555555555555555551170, so `(a/b)*b + a%b != a`. `fuzz_math` asserts the
  quotient/remainder identity only for `a >= b`.
- `BigInteger(std::string)` never terminates on non-digit characters (the digit loop never zeroes the buffer),
  so `fuzz_math` feeds it decimal strings only.
- `BigInteger::ModInverse` and `NativeInteger::ModInverse` divide by zero (UBSan) when gcd(a, m) != 1 instead
  of throwing; `fuzz_math` calls them on coprime pairs only.
- `FindAutomorphismIndex2n` divides by zero for m = 0 (`nbtheory2.cpp:217`) and
  `FindAutomorphismIndex2nComplex` overflows `int` for m >= 2^31; `fuzz_math` uses 1 <= m < 2^24.
- Observed but not root-caused, so the harness stays out of these regions: Barrett `NativeInteger::ModMul(b,
  mod, mu)` disagreed with the 128-bit reference for tiny moduli (fuzz_math uses 20..60 bit moduli);
  `RootOfUnity(m, FirstPrime(60, m))` returned a value with root^m != 1 for m = 4096 (fuzz_math uses
  nBits <= 57); CKKS with a 50-bit first modulus and 40-bit scale at ring dimension 16 multiplied with error
  > 0.1 (fuzz_params uses a 60-bit first modulus).
