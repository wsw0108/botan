/*
* DSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dsa.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>

namespace Botan {

DSA_PublicKey::DSA_PublicKey(const AlgorithmIdentifier& alg_id,
                             const MemoryRegion<byte>& key_bits)
   {
   DataSource_Memory source(alg_id.parameters);
   this->group.BER_decode(source, DL_Group::ANSI_X9_57);
   BER_Decoder(key_bits).decode(this->y);

   core = DSA_Core(group, y);
   }

/**
* DSA_PublicKey Constructor
*/
DSA_PublicKey::DSA_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;

   core = DSA_Core(group, y);
   }

/**
* DSA Verification Function
*/
bool DSA_PublicKey::verify(const byte msg[], u32bit msg_len,
                           const byte sig[], u32bit sig_len) const
   {
   return core.verify(msg, msg_len, sig, sig_len);
   }

std::pair<AlgorithmIdentifier, MemoryVector<byte> >
DSA_PublicKey::subject_public_key_info() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              this->group.DER_encode(DL_Group::ANSI_X9_57));

   MemoryVector<byte> key_bits = DER_Encoder().encode(this->get_y()).get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/**
* Check DSA public key for consistency
*/
bool DSA_PublicKey::check_key(RandomNumberGenerator& rng,
                              bool strong) const
   {
   if(y < 2 || y >= group_p())
      return false;
   if(!group.verify_group(rng, strong))
      return false;
   return true;
   }

/**
* Create a DSA private key
*/
DSA_PrivateKey::DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                               const MemoryRegion<byte>& key_bits,
                               RandomNumberGenerator& rng)
   {
   DataSource_Memory source(alg_id.parameters);
   this->group.BER_decode(source, DL_Group::ANSI_X9_57);

   BER_Decoder(key_bits).decode(this->x);
   y = power_mod(group_g(), x, group_p());

   core = DSA_Core(group, y, x);

   load_check(rng);
   }

/**
* Create a DSA private key
*/
DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng,
                               const DL_Group& grp,
                               const BigInt& x_arg)
   {
   group = grp;
   x = x_arg;

   if(x == 0)
      x = BigInt::random_integer(rng, 2, group_q() - 1);

   y = power_mod(group_g(), x, group_p());

   core = DSA_Core(group, y, x);

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

/**
* DSA Signature Operation
*/
SecureVector<byte> DSA_PrivateKey::sign(const byte in[], u32bit length,
                                        RandomNumberGenerator& rng) const
   {
   const BigInt& q = group_q();

   BigInt k;
   do
      k.randomize(rng, q.bits());
   while(k >= q);

   return core.sign(in, length, k);
   }

std::pair<AlgorithmIdentifier, SecureVector<byte> >
DSA_PrivateKey::pkcs8_encoding() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              this->group.DER_encode(DL_Group::ANSI_X9_57));

   SecureVector<byte> key_bits =
      DER_Encoder().encode(this->get_x()).get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/**
* Check Private DSA Parameters
*/
bool DSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
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
         DSA_PublicKey pub = public_key();
         KeyPair::check_key(rng,
                            get_pk_signer(*this, "EMSA1(SHA-1)"),
                            get_pk_verifier(pub, "EMSA1(SHA-1)")
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
