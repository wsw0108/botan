/*
* Rabin-Williams
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rw.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/**
* RW_PublicKey Constructor
*/
RW_PublicKey::RW_PublicKey(const AlgorithmIdentifier&,
                           const MemoryRegion<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode(this->n)
         .decode(this->e)
      .verify_end()
   .end_cons();

   core = IF_Core(e, n);
   }

/**
* RW_PublicKey Constructor
*/
RW_PublicKey::RW_PublicKey(const BigInt& mod, const BigInt& exp)
   {
   n = mod;
   e = exp;
   core = IF_Core(e, n);
   }

/**
* Rabin-Williams Public Operation
*/
BigInt RW_PublicKey::public_op(const BigInt& i) const
   {
   if((i > (n >> 1)) || i.is_negative())
      throw Invalid_Argument(algo_name() + "::public_op: i > n / 2 || i < 0");

   BigInt r = core.public_op(i);
   if(r % 16 == 12) return r;
   if(r % 8 == 6)   return 2*r;

   r = n - r;
   if(r % 16 == 12) return r;
   if(r % 8 == 6)   return 2*r;

   throw Invalid_Argument(algo_name() + "::public_op: Invalid input");
   }

/**
* Rabin-Williams Verification Function
*/
SecureVector<byte> RW_PublicKey::verify(const byte in[], u32bit len) const
   {
   BigInt i(in, len);
   return BigInt::encode(public_op(i));
   }

/**
* Return the X.509 subjectPublicKeyInfo for a RW key
*/
std::pair<AlgorithmIdentifier, MemoryVector<byte> >
RW_PublicKey::subject_public_key_info() const
   {
   DER_Encoder key_bits;

   key_bits.start_cons(SEQUENCE)
              .encode(this->get_n())
              .encode(this->get_e())
           .end_cons();

   AlgorithmIdentifier alg_id(this->get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);

   return std::make_pair(alg_id, key_bits.get_contents());
   }

/**
* Check RW public parameters for consistency
*/
bool RW_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(n < 35 || n.is_even() || e < 2 || e.is_odd() || e >= n)
      return false;
   return true;
   }

/**
* Create a Rabin-Williams private key
*/
RW_PrivateKey::RW_PrivateKey(const AlgorithmIdentifier&,
                             const MemoryRegion<byte>& key_bits,
                             RandomNumberGenerator& rng)
   {
   u32bit version;

   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
      .decode(version)
      .decode(this->n)
      .decode(this->e)
      .decode(this->d)
      .decode(this->p)
      .decode(this->q)
      .decode(this->d1)
      .decode(this->d2)
      .decode(this->c)
      .end_cons();

   if(version != 0)
      throw Decoding_Error("Unknown PKCS #1 RW key format version");

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   load_check(rng);
   }

/**
* Create a Rabin-Williams private key
*/
RW_PrivateKey::RW_PrivateKey(RandomNumberGenerator& rng,
                             u32bit bits, u32bit exp)
   {
   if(bits < 512)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             to_string(bits) + " bits long");
   if(exp < 2 || exp % 2 == 1)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;
   p = random_prime(rng, (bits + 1) / 2, e / 2, 3, 4);
   q = random_prime(rng, bits - p.bits(), e / 2, ((p % 8 == 3) ? 7 : 3), 8);
   d = inverse_mod(e, lcm(p - 1, q - 1) >> 1);

   n = p * q;

   if(n.bits() != bits)
      throw Self_Test_Failure(algo_name() + " private key generation failed");

   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   gen_check(rng);
   }

/**
* RW_PrivateKey Constructor
*/
RW_PrivateKey::RW_PrivateKey(RandomNumberGenerator& rng,
                             const BigInt& prime1, const BigInt& prime2,
                             const BigInt& exp, const BigInt& d_exp,
                             const BigInt& mod)
   {
   p = prime1;
   q = prime2;
   e = exp;
   d = (d_exp > 0) ? d_exp : inverse_mod(e, lcm(p - 1, q - 1) >> 1);
   n = (mod > 0) ? mod : (p * q);

   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   load_check(rng);
   }

/**
* Encode RW key in the PKCS #1 v1.5 RSAPrivateKey format
*/
std::pair<AlgorithmIdentifier, SecureVector<byte> >
RW_PrivateKey::pkcs8_encoding() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);

   SecureVector<byte> key_bits =
      DER_Encoder()
        .start_cons(SEQUENCE)
           .encode(static_cast<u32bit>(0))
           .encode(this->n)
           .encode(this->e)
           .encode(this->d)
           .encode(this->p)
           .encode(this->q)
           .encode(this->d1)
           .encode(this->d2)
           .encode(this->c)
        .end_cons()
        .get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/**
* Rabin-Williams Signature Operation
*/
SecureVector<byte> RW_PrivateKey::sign(const byte in[], u32bit len,
                                       RandomNumberGenerator&) const
   {
   BigInt i(in, len);
   if(i >= n || i % 16 != 12)
      throw Invalid_Argument(algo_name() + "::sign: Invalid input");

   BigInt r;
   if(jacobi(i, n) == 1) r = core.private_op(i);
   else                  r = core.private_op(i >> 1);

   r = std::min(r, n - r);
   if(i != public_op(r))
      throw Self_Test_Failure(algo_name() + " private operation check failed");

   return BigInt::encode_1363(r, n.bytes());
   }

/**
* Check Private Rabin-Williams Parameters
*/
bool RW_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(n < 35 || n.is_even() || e < 2 || n.is_even())
      return false;

   if(d < 2 || p < 3 || q < 3 || p*q != n)
      return false;

   if(strong)
      {
      if(d1 != d % (p - 1) || d2 != d % (q - 1) || c != inverse_mod(q, p))
         return false;
      if(!check_prime(p, rng) || !check_prime(q, rng))
         return false;

      if((e * d) % (lcm(p - 1, q - 1) / 2) != 1)
         return false;

      try
         {
         KeyPair::check_key(rng,
                            get_pk_signer(*this, "EMSA2(SHA-1)"),
                            get_pk_verifier(*this, "EMSA2(SHA-1)")
            );
         }
      catch(Self_Test_Failure)
         {
         return false;
         }
      }

   return true;
   }

}
