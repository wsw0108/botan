/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rsa.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

/**
* RSA_PublicKey Constructor
*/
RSA_PublicKey::RSA_PublicKey(const AlgorithmIdentifier&,
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
* RSA_PublicKey Constructor
*/
RSA_PublicKey::RSA_PublicKey(const BigInt& mod, const BigInt& exp)
   {
   n = mod;
   e = exp;
   core = IF_Core(e, n);
   }

/**
* RSA Public Operation
*/
BigInt RSA_PublicKey::public_op(const BigInt& i) const
   {
   if(i >= n)
      throw Invalid_Argument(algo_name() + "::public_op: input is too large");
   return core.public_op(i);
   }

/**
* RSA Encryption Function
*/
SecureVector<byte> RSA_PublicKey::encrypt(const byte in[], u32bit len,
                                          RandomNumberGenerator&) const
   {
   BigInt i(in, len);
   return BigInt::encode_1363(public_op(i), n.bytes());
   }

/**
* RSA Verification Function
*/
SecureVector<byte> RSA_PublicKey::verify(const byte in[], u32bit len) const
   {
   BigInt i(in, len);
   return BigInt::encode(public_op(i));
   }

/**
* Return the X.509 subjectPublicKeyInfo for a RSA key
*/
std::pair<AlgorithmIdentifier, MemoryVector<byte> >
RSA_PublicKey::subject_public_key_info() const
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
* Check RSA public parameters for consistency
*/
bool RSA_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(n < 35 || n.is_even() || e < 3 || e.is_even() || e >= n)
      return false;
   return true;
   }

/**
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(const AlgorithmIdentifier&,
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
      throw Decoding_Error("Unknown PKCS #1 RSA key format version");

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   load_check(rng);
   }

/**
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng,
                               u32bit bits, u32bit exp)
   {
   if(bits < 512)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             to_string(bits) + " bits long");
   if(exp < 3 || exp % 2 == 0)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;
   p = random_prime(rng, (bits + 1) / 2, e);
   q = random_prime(rng, bits - p.bits(), e);
   d = inverse_mod(e, lcm(p - 1, q - 1));

   n = p * q;
   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   gen_check(rng);

   if(n.bits() != bits)
      throw Self_Test_Failure(algo_name() + " private key generation failed");
   }

/**
* RSA_PrivateKey Constructor
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng,
                               const BigInt& prime1, const BigInt& prime2,
                               const BigInt& exp, const BigInt& d_exp,
                               const BigInt& mod)
   {
   p = prime1;
   q = prime2;
   e = exp;
   d = d_exp;
   n = mod;

   if(d == 0)
      d = inverse_mod(e, lcm(p - 1, q - 1));

   if(n == 0)
      n = p * q;

   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   load_check(rng);
   }

/**
* RSA Private Operation
*/
BigInt RSA_PrivateKey::private_op(const byte in[], u32bit length) const
   {
   BigInt i(in, length);
   if(i >= n)
      throw Invalid_Argument(algo_name() + "::private_op: input is too large");

   BigInt r = core.private_op(i);
   if(i != public_op(r))
      throw Self_Test_Failure(algo_name() + " private operation check failed");
   return r;
   }

/**
* RSA Decryption Operation
*/
SecureVector<byte> RSA_PrivateKey::decrypt(const byte in[], u32bit len) const
   {
   return BigInt::encode(private_op(in, len));
   }

/**
* RSA Signature Operation
*/
SecureVector<byte> RSA_PrivateKey::sign(const byte in[], u32bit len,
                                        RandomNumberGenerator&) const
   {
   return BigInt::encode_1363(private_op(in, len), n.bytes());
   }

/**
* Encode RW key in the PKCS #1 v1.5 RSAPrivateKey format
*/
std::pair<AlgorithmIdentifier, SecureVector<byte> >
RSA_PrivateKey::pkcs8_encoding() const
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
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(n < 35 || n.is_even() || e < 3 || e.is_even() || d < 2 || p < 3 || q < 3 || p*q != n)
      return false;

   if(strong)
      {
      if(d1 != d % (p - 1) || d2 != d % (q - 1) || c != inverse_mod(q, p))
         return false;
      if(!check_prime(p, rng) || !check_prime(q, rng))
         return false;

      if((e * d) % lcm(p - 1, q - 1) != 1)
         return false;

      try
         {
         KeyPair::check_key(rng,
                            get_pk_encryptor(*this, "EME1(SHA-1)"),
                            get_pk_decryptor(*this, "EME1(SHA-1)")
            );

         KeyPair::check_key(rng,
                            get_pk_signer(*this, "EMSA4(SHA-1)"),
                            get_pk_verifier(*this, "EMSA4(SHA-1)")
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
