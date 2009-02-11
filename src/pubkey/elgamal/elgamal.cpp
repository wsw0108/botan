/*
* ElGamal Source File
* (C) 1999-2009 Jack Lloyd
*/

#include <botan/elgamal.h>
#include <botan/ber_dec.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/der_enc.h>
#include <botan/util.h>

namespace Botan {

ElGamal_PublicKey::ElGamal_PublicKey(const AlgorithmIdentifier& alg_id,
                                     const MemoryRegion<byte>& key_bits)
   {
   DataSource_Memory source(alg_id.parameters);
   this->group.BER_decode(source, DL_Group::ANSI_X9_42);
   BER_Decoder(key_bits).decode(this->y);

   core = ELG_Core(group, y);
   }

/**
* ElGamal_PublicKey Constructor
*/
ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   core = ELG_Core(group, y);
   }

/**
* ElGamal Encryption Function
*/
SecureVector<byte>
ElGamal_PublicKey::encrypt(const byte in[], u32bit length,
                           RandomNumberGenerator& rng) const
   {
   BigInt k(rng, 2 * dl_work_factor(group_p().bits()));
   return core.encrypt(in, length, k);
   }

std::pair<AlgorithmIdentifier, MemoryVector<byte> >
ElGamal_PublicKey::subject_public_key_info() const
   {
   AlgorithmIdentifier alg_id(get_oid(),
                              group.DER_encode(DL_Group::ANSI_X9_42));

   MemoryVector<byte> key_bits = DER_Encoder().encode(get_y()).get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/**
* Check ElGamal public key for consistency
*/
bool ElGamal_PublicKey::check_key(RandomNumberGenerator& rng,
                                  bool strong) const
   {
   if(y < 2 || y >= group_p())
      return false;
   if(!group.verify_group(rng, strong))
      return false;
   return true;
   }

/**
* ElGamal_PrivateKey Constructor
*/
ElGamal_PrivateKey::ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                                       const MemoryRegion<byte>& key_bits,
                                       RandomNumberGenerator& rng)
   {
   DataSource_Memory source(alg_id.parameters);
   group.BER_decode(source, DL_Group::ANSI_X9_57);

   BER_Decoder(key_bits).decode(x);
   y = power_mod(group_g(), x, group_p());

   core = ELG_Core(rng, group, y, x);

   load_check(rng);
   }

/**
* ElGamal_PrivateKey Constructor
*/
ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng,
                                       const DL_Group& grp,
                                       const BigInt& x_arg)
   {
   group = grp;
   x = x_arg;

   if(x == 0)
      x.randomize(rng, 2 * dl_work_factor(group_p().bits()));

   y = power_mod(group_g(), x, group_p());
   core = ELG_Core(rng, group, y, x);

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

/**
* ElGamal Decryption Function
*/
SecureVector<byte> ElGamal_PrivateKey::decrypt(const byte in[],
                                               u32bit length) const
   {
   return core.decrypt(in, length);
   }

/**
* Decode ElGamal private key
*/
std::pair<AlgorithmIdentifier, SecureVector<byte> >
ElGamal_PrivateKey::pkcs8_encoding() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              this->group.DER_encode(DL_Group::ANSI_X9_42));

   SecureVector<byte> key_bits =
      DER_Encoder().encode(this->get_x()).get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/**
* Check Private ElGamal Parameters
*/
bool ElGamal_PrivateKey::check_key(RandomNumberGenerator& rng,
                                   bool strong) const
   {
   const BigInt& p = group_p();
   const BigInt& g = group_g();

   if(y < 2 || y >= p || x < 2 || x >= p)
      return false;
   if(!group.verify_group(rng, strong))
      return false;

   if(strong)
      {
      if(y != power_mod(g, x, p))
         return false;

      try
         {
         KeyPair::check_key(rng,
                            get_pk_encryptor(*this, "EME1(SHA-1)"),
                            get_pk_decryptor(*this, "EME1(SHA-1)")
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
