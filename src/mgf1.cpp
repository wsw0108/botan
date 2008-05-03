/*************************************************
* MGF1 Source File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/mgf1.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>
#include <botan/bit_ops.h>
#include <algorithm>
#include <memory>

namespace Botan {

/*************************************************
* MGF1 Mask Generation Function                  *
*************************************************/
void MGF1::mask(const byte in[], length_type in_len, byte out[],
                length_type out_len) const
   {
   length_type counter = 0;

   std::auto_ptr<HashFunction> hash(get_hash(hash_name));

   while(out_len)
      {
      hash->update(in, in_len);
      for(length_type j = 0; j != 4; ++j)
         hash->update(get_byte(j, counter));
      SecureVector<byte> buffer = hash->final();

      length_type xored = std::min(buffer.size(), out_len);
      xor_buf(out, buffer.begin(), xored);
      out += xored;
      out_len -= xored;

      ++counter;
      }
   }

/*************************************************
* MGF1 Constructor                               *
*************************************************/
MGF1::MGF1(const std::string& h_name) : hash_name(h_name)
   {
   if(!have_hash(hash_name))
      throw Algorithm_Not_Found(hash_name);
   }

}
