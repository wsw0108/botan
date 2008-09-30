/***r**********************************************
* Buffered EntropySource Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BUFFERED_ES_H__
#define BOTAN_BUFFERED_ES_H__

#include <botan/rng.h>
#include <botan/secmem.h>

namespace Botan {

/*************************************************
* Buffered EntropySource                         *
*************************************************/
class BOTAN_DLL Buffered_EntropySource : public EntropySource
   {
   public:
      length_type slow_poll(byte[], length_type);
      length_type fast_poll(byte[], length_type);
   protected:
      Buffered_EntropySource();
      length_type copy_out(byte[], length_type, length_type);

      void add_bytes(const void*, length_type);
      void add_bytes(u64bit);

      virtual void do_slow_poll() = 0;
      virtual void do_fast_poll();
   private:
      SecureVector<byte> buffer;
      length_type write_pos, read_pos;
      bool done_slow_poll;
   };

}

#endif
