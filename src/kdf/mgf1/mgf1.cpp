/*************************************************
* MGF1 Source File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/mgf1.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>
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
MGF1::MGF1(HashFunction* h) : hash(h)
   {
   if(!hash)
      throw Invalid_Argument("MGF1 given null hash object");
   }

/*************************************************
* MGF1 Destructor                                *
*************************************************/
MGF1::~MGF1()
   {
   delete hash;
   }

}
