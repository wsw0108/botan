/*************************************************
* SecureQueue Header File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SECURE_QUEUE_H__
#define BOTAN_SECURE_QUEUE_H__

#include <botan/data_src.h>
#include <botan/filter.h>

namespace Botan {

/*************************************************
* SecureQueue                                    *
*************************************************/
class BOTAN_DLL SecureQueue : public Fanout_Filter, public DataSource
   {
   public:
      void write(const byte[], length_type);

      length_type read(byte[], length_type);
      length_type peek(byte[], length_type, length_type = 0) const;

      bool end_of_data() const;
      length_type size() const;
      bool attachable() { return false; }

      SecureQueue& operator=(const SecureQueue&);
      SecureQueue();
      SecureQueue(const SecureQueue&);
      ~SecureQueue() { destroy(); }
   private:
      void destroy();
      class SecureQueueNode* head;
      class SecureQueueNode* tail;
   };

}

#endif
