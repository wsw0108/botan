/*************************************************
* EMSA2 Header File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA2_H__
#define BOTAN_EMSA2_H__

#include <botan/pk_pad.h>

namespace Botan {

/*************************************************
* EMSA2                                          *
*************************************************/
class BOTAN_DLL EMSA2 : public EMSA
   {
   public:
      EMSA2(HashFunction* hash);
      ~EMSA2() { delete hash; }
   private:
      void update(const byte[], length_type);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, length_type,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  length_type) throw();

      SecureVector<byte> empty_hash;
      HashFunction* hash;
      byte hash_id;
   };

}

#endif
