/*************************************************
* EMSA-Raw Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA_RAW_H__
#define BOTAN_EMSA_RAW_H__

#include <botan/pk_pad.h>

namespace Botan {

/*************************************************
* EMSA-Raw                                       *
*************************************************/
class BOTAN_DLL EMSA_Raw : public EMSA
   {
   private:
      void update(const byte[], length_type);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, length_type,
                                     RandomNumberGenerator&);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  length_type) throw();

      SecureVector<byte> message;
   };

}

#endif
