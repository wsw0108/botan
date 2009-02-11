/*
* ElGamal Header File
* (C) 1999-2007 Jack Lloyd
*/

#ifndef BOTAN_ELGAMAL_H__
#define BOTAN_ELGAMAL_H__

#include <botan/dl_algo.h>
#include <botan/elg_core.h>

namespace Botan {

/**
* ElGamal Public Key
*/
class BOTAN_DLL ElGamal_PublicKey : public PK_Encrypting_Key,
                                    public virtual DL_Scheme_PublicKey
   {
   public:
      ElGamal_PublicKey(const AlgorithmIdentifier& alg_id,
                        const MemoryRegion<byte>& key_bits);

      ElGamal_PublicKey(const DL_Group& group, const BigInt& y);

      std::string algo_name() const { return "ElGamal"; }
      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

      SecureVector<byte> encrypt(const byte msg[], u32bit msg_len,
                                 RandomNumberGenerator& rng) const;

      u32bit max_input_bits() const;
   protected:
      ElGamal_PublicKey() {}

      ELG_Core core;
   };

/**
* ElGamal Private Key
*/
class BOTAN_DLL ElGamal_PrivateKey : public ElGamal_PublicKey,
                                     public PK_Decrypting_Key,
                                     public virtual DL_Scheme_PrivateKey
   {
   public:
      ElGamal_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group,
                         const BigInt& x = 0);

      ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                         const MemoryRegion<byte>& key_bits,
                         RandomNumberGenerator& rng);

      SecureVector<byte> decrypt(const byte msg[], u32bit msg_len) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;
   };

}

#endif
