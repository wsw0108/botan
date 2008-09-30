/*************************************************
* EME1 Source File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eme1.h>
#include <botan/mgf1.h>
#include <memory>

namespace Botan {

/*************************************************
* EME1 Pad Operation                             *
*************************************************/
SecureVector<byte> EME1::pad(const byte in[], u32bit in_length,
                             length_type key_length,
                             RandomNumberGenerator& rng) const
   {
   key_length /= 8;

   if(in_length > key_length - 2*HASH_LENGTH - 1)
      throw Exception("EME1: Input is too large");

   SecureVector<byte> out(key_length);

   out.clear();

   rng.randomize(out, HASH_LENGTH);

   out.copy(HASH_LENGTH, Phash, Phash.size());
   out[out.size() - in_length - 1] = 0x01;
   out.copy(out.size() - in_length, in, in_length);
   mgf->mask(out, HASH_LENGTH, out + HASH_LENGTH, out.size() - HASH_LENGTH);
   mgf->mask(out + HASH_LENGTH, out.size() - HASH_LENGTH, out, HASH_LENGTH);

   return out;
   }

/*************************************************
* EME1 Unpad Operation                           *
*************************************************/
SecureVector<byte> EME1::unpad(const byte in[], length_type in_length,
                               length_type key_length) const
   {
   key_length /= 8;
   if(in_length > key_length)
      throw Decoding_Error("Invalid EME1 encoding");

   SecureVector<byte> tmp(key_length);
   tmp.copy(key_length - in_length, in, in_length);

   mgf->mask(tmp + HASH_LENGTH, tmp.size() - HASH_LENGTH, tmp, HASH_LENGTH);
   mgf->mask(tmp, HASH_LENGTH, tmp + HASH_LENGTH, tmp.size() - HASH_LENGTH);

   for(length_type j = 0; j != Phash.size(); ++j)
      if(tmp[j+HASH_LENGTH] != Phash[j])
         throw Decoding_Error("Invalid EME1 encoding");

   for(length_type j = HASH_LENGTH + Phash.size(); j != tmp.size(); ++j)
      {
      if(tmp[j] && tmp[j] != 0x01)
         throw Decoding_Error("Invalid EME1 encoding");
      if(tmp[j] && tmp[j] == 0x01)
         {
         SecureVector<byte> retval(tmp + j + 1, tmp.size() - j - 1);
         return retval;
         }
      }
   throw Decoding_Error("Invalid EME1 encoding");
   }

/*************************************************
* Return the max input size for a given key size *
*************************************************/
length_type EME1::maximum_input_size(length_type keybits) const
   {
   if(keybits / 8 > 2*HASH_LENGTH + 1)
      return ((keybits / 8) - 2*HASH_LENGTH - 1);
   else
      return 0;
   }

/*************************************************
* EME1 Constructor                               *
*************************************************/
EME1::EME1(HashFunction* hash, const std::string& P) :
   HASH_LENGTH(hash->OUTPUT_LENGTH)
   {
   Phash = hash->process(P);
   mgf = new MGF1(hash);
   }

}
