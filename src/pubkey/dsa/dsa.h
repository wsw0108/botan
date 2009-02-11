/*
* DSA Header File
* (C) 1999-2009 Jack Lloyd
*/

#ifndef BOTAN_DSA_H__
#define BOTAN_DSA_H__

#include <botan/dl_group.h>
#include <botan/dsa_core.h>
#include <botan/rng.h>
#include <botan/pk_keys.h>

namespace Botan {

/**
* DSA Public Key
*/
class BOTAN_DLL DSA_PublicKey : public PK_Verifying_wo_MR_Key
   {
   public:
      DSA_PublicKey(const AlgorithmIdentifier& alg_id,
                    const MemoryRegion<byte>& key_bits);

      DSA_PublicKey(const DL_Group& group, const BigInt& x);

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

      bool check_key(RandomNumberGenerator& rng, bool) const;

      std::string algo_name() const { return "DSA"; }

      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const;
      u32bit max_input_bits() const;

      /**
      * Verify a DSA signature
      * @param msg the message hash
      * @param msg_len length of msg in bytes
      * @param sig the signature to check
      * @param sig_len the length of sig in bytes
      * @return if the signature is valid
      */
      bool verify(const byte msg[], u32bit msg_len,
                  const byte sig[], u32bit sig_len) const;

      std::pair<AlgorithmIdentifier, MemoryVector<byte> >
         subject_public_key_info() const;
   protected:
      DSA_PublicKey() {}

      DSA_Core core;
      DL_Group group;
      BigInt y;
   };

/**
* DSA Private Key
*/
class BOTAN_DLL DSA_PrivateKey : public DSA_PublicKey,
                                 public PK_Signing_Key
   {
   public:
      DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                     const MemoryRegion<byte>& key_bits,
                     RandomNumberGenerator& rng);

      DSA_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group,
                     const BigInt& x = 0);

      SecureVector<byte> sign(const byte msg[], u32bi msg_lent,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

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
