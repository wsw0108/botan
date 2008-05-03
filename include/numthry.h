/*************************************************
* Number Theory Header File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_NUMBTHRY_H__
#define BOTAN_NUMBTHRY_H__

#include <botan/bigint.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>

namespace Botan {

/*************************************************
* Fused Arithmetic Operations                    *
*************************************************/
BigInt BOTAN_DLL mul_add(const BigInt&, const BigInt&, const BigInt&);
BigInt BOTAN_DLL sub_mul(const BigInt&, const BigInt&, const BigInt&);

/*************************************************
* Number Theory Functions                        *
*************************************************/
inline BigInt abs(const BigInt& n) { return n.abs(); }

void BOTAN_DLL divide(const BigInt&, const BigInt&, BigInt&, BigInt&);

BigInt BOTAN_DLL gcd(const BigInt&, const BigInt&);
BigInt BOTAN_DLL lcm(const BigInt&, const BigInt&);

BigInt BOTAN_DLL square(const BigInt&);
BigInt BOTAN_DLL inverse_mod(const BigInt&, const BigInt&);
s32bit BOTAN_DLL jacobi(const BigInt&, const BigInt&);

BigInt BOTAN_DLL power_mod(const BigInt&, const BigInt&, const BigInt&);

/*************************************************
* Utility Functions                              *
*************************************************/
length_type BOTAN_DLL low_zero_bits(const BigInt&);

/*************************************************
* Primality Testing                              *
*************************************************/
bool BOTAN_DLL check_prime(const BigInt&);
bool BOTAN_DLL is_prime(const BigInt&);
bool BOTAN_DLL verify_prime(const BigInt&);

s32bit BOTAN_DLL simple_primality_tests(const BigInt&);
bool BOTAN_DLL passes_mr_tests(const BigInt&, length_type = 1);
bool BOTAN_DLL run_primality_tests(const BigInt&, length_type = 1);

/*************************************************
* Random Number Generation                       *
*************************************************/
BigInt BOTAN_DLL random_integer(length_type);
BigInt BOTAN_DLL random_integer(const BigInt&, const BigInt&);
BigInt BOTAN_DLL random_prime(length_type, const BigInt& = 1,
                              length_type = 1, length_type = 2);

BigInt BOTAN_DLL random_safe_prime(length_type);

/*************************************************
* Prime Numbers                                  *
*************************************************/
const length_type PRIME_TABLE_SIZE = 6541;
const length_type PRIME_PRODUCTS_TABLE_SIZE = 256;

extern const u16bit BOTAN_DLL PRIMES[];
extern const u64bit PRIME_PRODUCTS[];

/*************************************************
* Miller-Rabin Primality Tester                  *
*************************************************/
class BOTAN_DLL MillerRabin_Test
   {
   public:
      bool passes_test(const BigInt&);
      MillerRabin_Test(const BigInt&);
   private:
      BigInt n, r, n_minus_1;
      length_type s;
      Fixed_Exponent_Power_Mod pow_mod;
      Modular_Reducer reducer;
   };

}

#endif
