/*
* DSA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DSA_H__
#define BOTAN_DSA_H__

#include <botan/dl_algo.h>
#include <botan/dsa_core.h>

namespace Botan {

/*
* DSA Public Key
*/
class BOTAN_DLL DSA_PublicKey : public PK_Verifying_wo_MR_Key,
                                public DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const { return "DSA"; }

      DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }
      u32bit message_parts() const { return 2; }
      u32bit message_part_size() const;

      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      u32bit max_input_bits() const;

      X509_Encoder* x509_encoder() const
         { return DL_Scheme_PublicKey::x509_encoder(); }
      X509_Decoder* x509_decoder()
         { return DL_Scheme_PublicKey::x509_decoder(); }

      DSA_PublicKey() {}
      DSA_PublicKey(const DL_Group&, const BigInt&);
   protected:
      DSA_Core core;
   private:
      void X509_load_hook();
   };

/*
* DSA Private Key
*/
class BOTAN_DLL DSA_PrivateKey : public PK_Signing_Key,
                                 public DL_Scheme_PrivateKey
   {
   public:
      /**
        Return a new public key matching this private key
      */
      DSA_PublicKey* public_key() const;

      SecureVector<byte> sign(const byte[], u32bit,
                              RandomNumberGenerator& rng) const;

      bool check_key(RandomNumberGenerator& rng, bool) const;

      PKCS8_Encoder* pkcs8_encoder() const
         { return DL_Scheme_PrivateKey::pkcs8_encoder(); }
      PKCS8_Decoder* pkcs8_decoder(RandomNumberGenerator& rng)
         { return DL_Scheme_PrivateKey::pkcs8_decoder(rng); }

      DSA_PrivateKey() {}
      DSA_PrivateKey(RandomNumberGenerator&, const DL_Group&,
                     const BigInt& = 0);
   private:
      DSA_Core core;

      void PKCS8_load_hook(RandomNumberGenerator& rng, bool = false);
   };

}

#endif
