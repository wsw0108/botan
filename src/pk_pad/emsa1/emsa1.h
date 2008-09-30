/*************************************************
* EMSA1 Header File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA1_H__
#define BOTAN_EMSA1_H__

#include <botan/pk_pad.h>

namespace Botan {

/*************************************************
* EMSA1                                          *
*************************************************/
class BOTAN_DLL EMSA1 : public EMSA
   {
   public:
      EMSA1(HashFunction* h) : hash(h) {}
      ~EMSA1() { delete hash; }
   private:
      void update(const byte[], length_type);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, length_type,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  length_type) throw();

      HashFunction* hash;
   };

}

#endif
