/*
* GF(p) modulus class
*
* (C) 2008 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gfp_modulus.h>
#include <botan/numthry.h>

namespace Botan {

namespace {

/**
* Calculates R=b^n (here b=2) with R>m (and R being as small as
* possible) for an odd modulus m. No check for parity is performed!
*/
BigInt montgm_calc_r_oddmod(const BigInt& prime)
   {
   return BigInt(1) << (prime.sig_words() * BOTAN_MP_WORD_BITS);
   }

/**
*calculates m' with r*r^-1 - m*m' = 1
* where r^-1 is the multiplicative inverse of r to the modulus m
*/
BigInt montgm_calc_m_dash(const BigInt& r, const BigInt& m, const BigInt& r_inv)
   {
   return (((r * r_inv) - BigInt(1)) / m);
   }

}

GFpModulus::GFpModulus(const BigInt& p_arg) : p(p_arg)
   {
   r = montgm_calc_r_oddmod(p);
   r_inv = inverse_mod(r, p);
   p_dash = montgm_calc_m_dash(r, p, r_inv);
   }

}
