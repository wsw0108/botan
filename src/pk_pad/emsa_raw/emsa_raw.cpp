/*************************************************
* EMSA-Raw Source File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/emsa_raw.h>

namespace Botan {

/*************************************************
* EMSA-Raw Encode Operation                      *
*************************************************/
void EMSA_Raw::update(const byte input[], length_type length)
   {
   message.append(input, length);
   }

/*************************************************
* Return the raw (unencoded) data                *
*************************************************/
SecureVector<byte> EMSA_Raw::raw_data()
   {
   SecureVector<byte> buf = message;
   message.destroy();
   return buf;
   }

/*************************************************
* EMSA-Raw Encode Operation                      *
*************************************************/
SecureVector<byte> EMSA_Raw::encoding_of(const MemoryRegion<byte>& msg,
                                         length_type,
                                         RandomNumberGenerator&)
   {
   return msg;
   }

/*************************************************
* EMSA-Raw Verify Operation                      *
*************************************************/
bool EMSA_Raw::verify(const MemoryRegion<byte>& coded,
                      const MemoryRegion<byte>& raw,
                      length_type) throw()
   {
   return (coded == raw);
   }

}
