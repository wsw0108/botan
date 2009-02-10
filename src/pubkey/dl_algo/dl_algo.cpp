/*************************************************
* DL Scheme Source File                          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/dl_algo.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

std::pair<AlgorithmIdentifier, MemoryVector<byte> >
DL_Scheme_PublicKey::subject_public_key_info() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              this->group.DER_encode(this->group_format()));

   MemoryVector<byte> key_bits = DER_Encoder().encode(this->get_y()).get_contents();

   return std::make_pair(alg_id, key_bits);
   }

std::pair<AlgorithmIdentifier, SecureVector<byte> >
DL_Scheme_PrivateKey::pkcs8_encoding() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              this->group.DER_encode(this->group_format()));

   SecureVector<byte> key_bits =
      DER_Encoder().encode(this->get_x()).get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/*************************************************
* Return the PKCS #8 private key decoder         *
*************************************************/
PKCS8_Decoder* DL_Scheme_PrivateKey::pkcs8_decoder(RandomNumberGenerator& rng)
   {
   class DL_Scheme_Decoder : public PKCS8_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            DataSource_Memory source(alg_id.parameters);
            key->group.BER_decode(source, key->group_format());
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {
            BER_Decoder(bits).decode(key->x);
            key->PKCS8_load_hook(rng);
            }

         DL_Scheme_Decoder(DL_Scheme_PrivateKey* k, RandomNumberGenerator& r) :
            key(k), rng(r) {}
      private:
         DL_Scheme_PrivateKey* key;
         RandomNumberGenerator& rng;
      };

   return new DL_Scheme_Decoder(this, rng);
   }

/*************************************************
* Check Public DL Parameters                     *
*************************************************/
bool DL_Scheme_PublicKey::check_key(RandomNumberGenerator& rng,
                                    bool strong) const
   {
   if(y < 2 || y >= group_p())
      return false;
   if(!group.verify_group(rng, strong))
      return false;
   return true;
   }

/*************************************************
* Check DL Scheme Private Parameters             *
*************************************************/
bool DL_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   const BigInt& p = group_p();
   const BigInt& g = group_g();

   if(y < 2 || y >= p || x < 2 || x >= p)
      return false;
   if(!group.verify_group(rng, strong))
      return false;

   if(!strong)
      return true;

   if(y != power_mod(g, x, p))
      return false;

   return true;
   }

}
