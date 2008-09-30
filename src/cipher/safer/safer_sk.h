/*************************************************
* SAFER-SK Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SAFER_SK_H__
#define BOTAN_SAFER_SK_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* SAFER-SK                                       *
*************************************************/
class BOTAN_DLL SAFER_SK : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const;
      BlockCipher* clone() const;
      SAFER_SK(length_type);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], length_type);

      static const byte EXP[256];
      static const byte LOG[512];
      static const byte BIAS[208];
      static const byte KEY_INDEX[208];
      SecureVector<byte> EK;
      const length_type ROUNDS;
   };

}

#endif
