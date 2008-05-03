/*************************************************
* RC5 Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RC5_H__
#define BOTAN_RC5_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* RC5                                            *
*************************************************/
class BOTAN_DLL RC5 : public BlockCipher
   {
   public:
      void clear() throw() { S.clear(); }
      std::string name() const;
      BlockCipher* clone() const { return new RC5(ROUNDS); }
      RC5(length_type);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], length_type);
      SecureVector<u32bit> S;
      const length_type ROUNDS;
   };

}

#endif
