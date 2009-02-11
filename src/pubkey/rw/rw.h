/*
* Rabin-Williams Header File
* (C) 1999-2009 Jack Lloyd
*/

#ifndef BOTAN_RABIN_WILLIAMS_H__
#define BOTAN_RABIN_WILLIAMS_H__

#include <botan/pk_keys.h>
#include <botan/if_core.h>

namespace Botan {

/**
* Rabin-Williams Public Key
*/
class BOTAN_DLL RW_PublicKey : public PK_Verifying_with_MR_Key
   {
   public:
      RW_PublicKey() {}

      RW_PublicKey(const AlgorithmIdentifier& alg_id,
                   const MemoryRegion<byte>& key_bits);

      RW_PublicKey(const BigInt&, const BigInt&);

      std::string algo_name() const { return "RW"; }

      SecureVector<byte> verify(const byte[], u32bit) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

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
* Rabin-Williams Private Key
*/
class BOTAN_DLL RW_PrivateKey : public RW_PublicKey,
                                public PK_Signing_Key
   {
   public:
      RW_PrivateKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits,
                    RandomNumberGenerator& rng);

      RW_PrivateKey(RandomNumberGenerator& rng,
                    const BigInt& p,
                    const BigInt& q,
                    const BigInt& e,
                    const BigInt& d = 0,
                    const BigInt& n = 0);

      RW_PrivateKey(RandomNumberGenerator& rng, u32bit bits, u32bit exponent = 2);

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

      /**
      * Sign a message
      * @param msg the message contents
      * @param msg_len the length of mssg in bytes
      * @param rng the random number generator
      */
      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      std::pair<AlgorithmIdentifier, SecureVector<byte> >
         pkcs8_encoding() const;
   private:
      BigInt d, p, q, d1, d2, c;
   };

}

#endif
