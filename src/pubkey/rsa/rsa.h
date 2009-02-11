/*
* RSA Header File
* (C) 1999-2009 Jack Lloyd
*/

#ifndef BOTAN_RSA_H__
#define BOTAN_RSA_H__

#include <botan/pk_keys.h>
#include <botan/if_core.h>

namespace Botan {

/**
* RSA Public Key
*/
class BOTAN_DLL RSA_PublicKey : public PK_Encrypting_Key,
                                public PK_Verifying_with_MR_Key
   {
   public:
      RSA_PublicKey() {}

      RSA_PublicKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits);

      RSA_PublicKey(const BigInt& n, const BigInt& e);

      std::string algo_name() const { return "RSA"; }

      bool check_key(RandomNumberGenerator& rng, bool) const;

      SecureVector<byte> encrypt(const byte msg[], u32bit msg_len,
                                 RandomNumberGenerator& rng) const;

      SecureVector<byte> verify(const byte sig[], u32bit sig_len) const;

      /**
      * Get n = p * q.
      * @return n
      */
      const BigInt& get_n() const { return n; }

      /**
      * Get the public exponent used by the key.
      * @return the public exponent
      */
      const BigInt& get_e() const { return e; }

      u32bit max_input_bits() const { return (n.bits() - 1); }

      std::pair<AlgorithmIdentifier, MemoryVector<byte> >
         subject_public_key_info() const;
   protected:
      BigInt public_op(const BigInt&) const;

      BigInt n, e;
      IF_Core core;
   };

/**
* RSA Private Key class.
*/
class BOTAN_DLL RSA_PrivateKey : public RSA_PublicKey,
                                 public PK_Decrypting_Key,
                                 public PK_Signing_Key
   {
   public:

      /**
      * Construct a private key from the specified parameters.
      * @param rng the random number generator to use
      * @param prime1 the first prime
      * @param prime2 the second prime
      * @param exp the exponent
      * @param d_exp if specified, this has to be d with
      * exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
      * the constructor to calculate it.
      * @param n if specified, this must be n = p * q. Leave it as 0
      * if you wish to the constructor to calculate it.
      */
      RSA_PrivateKey(RandomNumberGenerator& rng,
                     const BigInt& p, const BigInt& q, const BigInt& e,
                     const BigInt& d = 0, const BigInt& n = 0);

      /**
      * Create a new private key with the specified bit length
      * @param rng the random number generator to use
      * @param bits the desired bit length of the private key
      * @param exp the public exponent to be used
      */
      RSA_PrivateKey(RandomNumberGenerator& rng,
                     u32bit bits, u32bit exp = 65537);

      RSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                     const MemoryRegion<byte>& key_bits,
                     RandomNumberGenerator& rng);

      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng) const;

      SecureVector<byte> decrypt(const byte ciphertext[], u32bit len) const;

      bool check_key(RandomNumberGenerator& rng, bool strong_checks) const;

      /**
      * Get the first prime p.
      * @return the prime p
      */
      const BigInt& get_p() const { return p; }

      /**
      * Get the second prime q.
      * @return the prime q
      */
      const BigInt& get_q() const { return q; }

      /**
      * Get d with exp * d = 1 mod (p - 1, q - 1).
      * @return d
      */
      const BigInt& get_d() const { return d; }

      std::pair<AlgorithmIdentifier, SecureVector<byte> >
         pkcs8_encoding() const;
   private:
      BigInt private_op(const byte[], u32bit) const;

      BigInt d, p, q, d1, d2, c;
   };

}

#endif
