/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ELGAMAL_H__
#define BOTAN_ELGAMAL_H__

#include <botan/pk_keys.h>
#include <botan/dl_group.h>
#include <botan/rng.h>
#include <botan/elg_core.h>

namespace Botan {

/**
* ElGamal Public Key
*/
class BOTAN_DLL ElGamal_PublicKey : public PK_Encrypting_Key
   {
   public:
      ElGamal_PublicKey(const AlgorithmIdentifier& alg_id,
                        const MemoryRegion<byte>& key_bits);

      ElGamal_PublicKey(const DL_Group& group, const BigInt& y);

      std::string algo_name() const { return "ElGamal"; }

      /**
      * Get the DL domain parameters of this key.
      * @return the DL domain parameters of this key
      */
      const DL_Group& get_domain() const { return group; }

      /**
      * Get the public value y with y = g^x mod p where x is the secret key.
      */
      const BigInt& get_y() const { return y; }

      /**
      * Get the prime p of the underlying DL group.
      * @return the prime p
      */
      const BigInt& group_p() const { return group.get_p(); }

      /**
      * Get the prime q of the underlying DL group.
      * @return the prime q
      */
      const BigInt& group_q() const { return group.get_q(); }

      /**
      * Get the generator g of the underlying DL group.
      * @return the generator g
      */
      const BigInt& group_g() const { return group.get_g(); }

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      SecureVector<byte> encrypt(const byte msg[], u32bit msg_len,
                                 RandomNumberGenerator& rng) const;

      /**
      * Return the maximum input size in bits
      */
      u32bit max_input_bits() const { return (group_p().bits() - 1); }

      std::pair<AlgorithmIdentifier, MemoryVector<byte> >
         subject_public_key_info() const;
   protected:
      ElGamal_PublicKey() {}

      ELG_Core core;
      BigInt y;
      DL_Group group;
   };

/**
* ElGamal Private Key
*/
class BOTAN_DLL ElGamal_PrivateKey : public ElGamal_PublicKey,
                                     public PK_Decrypting_Key
   {
   public:
      ElGamal_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group,
                         const BigInt& x = 0);

      ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                         const MemoryRegion<byte>& key_bits,
                         RandomNumberGenerator& rng);

      SecureVector<byte> decrypt(const byte msg[], u32bit msg_len) const;

      bool check_key(RandomNumberGenerator& rng, bool strong) const;

      /**
      * Get the secret key x.
      * @return the secret key
      */
      const BigInt& get_x() const { return x; }

      std::pair<AlgorithmIdentifier, SecureVector<byte> >
         pkcs8_encoding() const;
   private:
      BigInt x;
   };

}

#endif
