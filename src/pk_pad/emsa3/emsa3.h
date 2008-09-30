/*************************************************
* EMSA3 Header File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA3_H__
#define BOTAN_EMSA3_H__

#include <botan/pk_pad.h>

namespace Botan {

/*************************************************
* EMSA3                                          *
*************************************************/
class BOTAN_DLL EMSA3 : public EMSA
   {
   public:
      EMSA3(HashFunction* hash);
      ~EMSA3() { delete hash; }
   private:
      void update(const byte[], length_type);

      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, length_type,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  length_type) throw();

      HashFunction* hash;
      SecureVector<byte> hash_id;
   };

}

#endif
