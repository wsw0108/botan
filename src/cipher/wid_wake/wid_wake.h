/*************************************************
* WiderWake Header File                          *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_WIDER_WAKE_H__
#define BOTAN_WIDER_WAKE_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* WiderWake4+1-BE                                *
*************************************************/
class BOTAN_DLL WiderWake_41_BE : public StreamCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "WiderWake4+1-BE"; }
      StreamCipher* clone() const { return new WiderWake_41_BE; }
      WiderWake_41_BE() : StreamCipher(16, 16, 1, 8) {}
   private:
      void cipher(const byte[], byte[], length_type);
      void key(const byte[], length_type);
      void resync(const byte[], length_type);

      void generate(length_type);

      SecureBuffer<byte, DEFAULT_BUFFERSIZE> buffer;
      SecureBuffer<u32bit, 256> T;
      SecureBuffer<u32bit, 5> state;
      SecureBuffer<u32bit, 4> t_key;
      length_type position;
   };

}

#endif
