/*************************************************
* ARC4 Header File                               *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ARC4_H__
#define BOTAN_ARC4_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* ARC4                                           *
*************************************************/
class BOTAN_DLL ARC4 : public StreamCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      StreamCipher* clone() const { return new ARC4(SKIP); }
      ARC4(length_type = 0);
      ~ARC4() { clear(); }
   private:
      void cipher(const byte[], byte[], length_type);
      void key(const byte[], length_type);
      void generate();

      const length_type SKIP;

      SecureBuffer<byte, DEFAULT_BUFFERSIZE> buffer;
      SecureBuffer<u32bit, 256> state;
      u32bit X, Y, position;
   };

}

#endif
