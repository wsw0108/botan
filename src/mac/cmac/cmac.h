/*************************************************
* CMAC Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CMAC_H__
#define BOTAN_CMAC_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* CMAC                                           *
*************************************************/
class BOTAN_DLL CMAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      MessageAuthenticationCode* clone() const;

      static SecureVector<byte> poly_double(const MemoryRegion<byte>& in,
                                            byte polynomial);

      CMAC(BlockCipher* e);
      ~CMAC();
   private:
      void add_data(const byte[], length_type);
      void final_result(byte[]);
      void key(const byte[], length_type);

      BlockCipher* e;
      SecureVector<byte> buffer, state, B, P;
      length_type position;
      byte polynomial;
   };

}

#endif
