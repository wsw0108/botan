/*************************************************
* Output Buffer Header File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_OUTPUT_BUFFER_H__
#define BOTAN_OUTPUT_BUFFER_H__

#include <botan/types.h>
#include <botan/pipe.h>
#include <deque>

namespace Botan {

/*************************************************
* Container of output buffers for Pipe           *
*************************************************/
class BOTAN_DLL Output_Buffers
   {
   public:
      length_type read(byte[], length_type, Pipe::message_id);
      length_type peek(byte[], length_type, length_type,
                       Pipe::message_id) const;

      length_type remaining(Pipe::message_id) const;

      void add(class SecureQueue*);
      void retire();

      Pipe::message_id message_count() const;

      Output_Buffers();
      ~Output_Buffers();
   private:
      class SecureQueue* get(Pipe::message_id) const;

      std::deque<SecureQueue*> buffers;
      Pipe::message_id offset;
   };

}

#endif
