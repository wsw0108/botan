/*************************************************
* SecureQueue Source File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/secqueue.h>
#include <algorithm>

namespace Botan {

/*************************************************
* SecureQueueNode                                *
*************************************************/
class SecureQueueNode
   {
   public:
      length_type write(const byte input[], length_type length)
         {
         length_type copied = std::min(length, buffer.size() - end);
         copy_mem(buffer + end, input, copied);
         end += copied;
         return copied;
         }
      length_type read(byte output[], length_type length)
         {
         length_type copied = std::min(length, end - start);
         copy_mem(output, buffer + start, copied);
         start += copied;
         return copied;
         }
      length_type peek(byte output[], length_type length,
                       length_type offset = 0)
         {
         const length_type left = end - start;
         if(offset >= left) return 0;
         length_type copied = std::min(length, left - offset);
         copy_mem(output, buffer + start + offset, copied);
         return copied;
         }
      length_type size() const { return (end - start); }
      SecureQueueNode()  { next = 0; start = end = 0; }
      ~SecureQueueNode() { next = 0; start = end = 0; }
   private:
      friend class SecureQueue;
      SecureQueueNode* next;
      SecureBuffer<byte, DEFAULT_BUFFERSIZE> buffer;
      length_type start, end;
   };

/*************************************************
* Create a SecureQueue                           *
*************************************************/
SecureQueue::SecureQueue()
   {
   set_next(0, 0);
   head = tail = new SecureQueueNode;
   }

/*************************************************
* Copy a SecureQueue                             *
*************************************************/
SecureQueue::SecureQueue(const SecureQueue& input) :
   Fanout_Filter(), DataSource()
   {
   set_next(0, 0);

   head = tail = new SecureQueueNode;
   SecureQueueNode* temp = input.head;
   while(temp)
      {
      write(temp->buffer + temp->start, temp->end - temp->start);
      temp = temp->next;
      }
   }

/*************************************************
* Destroy this SecureQueue                       *
*************************************************/
void SecureQueue::destroy()
   {
   SecureQueueNode* temp = head;
   while(temp)
      {
      SecureQueueNode* holder = temp->next;
      delete temp;
      temp = holder;
      }
   head = tail = 0;
   }

/*************************************************
* Copy a SecureQueue                             *
*************************************************/
SecureQueue& SecureQueue::operator=(const SecureQueue& input)
   {
   destroy();
   head = tail = new SecureQueueNode;
   SecureQueueNode* temp = input.head;
   while(temp)
      {
      write(temp->buffer + temp->start, temp->end - temp->start);
      temp = temp->next;
      }
   return (*this);
   }

/*************************************************
* Add some bytes to the queue                    *
*************************************************/
void SecureQueue::write(const byte input[], length_type length)
   {
   if(!head)
      head = tail = new SecureQueueNode;
   while(length)
      {
      const length_type n = tail->write(input, length);
      input += n;
      length -= n;
      if(length)
         {
         tail->next = new SecureQueueNode;
         tail = tail->next;
         }
      }
   }

/*************************************************
* Read some bytes from the queue                 *
*************************************************/
length_type SecureQueue::read(byte output[], length_type length)
   {
   length_type got = 0;
   while(length && head)
      {
      const length_type n = head->read(output, length);
      output += n;
      got += n;
      length -= n;
      if(head->size() == 0)
         {
         SecureQueueNode* holder = head->next;
         delete head;
         head = holder;
         }
      }
   return got;
   }

/*************************************************
* Read data, but do not remove it from queue     *
*************************************************/
length_type SecureQueue::peek(byte output[], length_type length,
                              length_type offset) const
   {
   SecureQueueNode* current = head;

   while(offset && current)
      {
      if(offset >= current->size())
         {
         offset -= current->size();
         current = current->next;
         }
      else
         break;
      }

   length_type got = 0;
   while(length && current)
      {
      const length_type n = current->peek(output, length, offset);
      offset = 0;
      output += n;
      got += n;
      length -= n;
      current = current->next;
      }
   return got;
   }

/*************************************************
* Return how many bytes the queue holds          *
*************************************************/
length_type SecureQueue::size() const
   {
   SecureQueueNode* current = head;
   length_type count = 0;

   while(current)
      {
      count += current->size();
      current = current->next;
      }
   return count;
   }

/*************************************************
* Test if the queue has any data in it           *
*************************************************/
bool SecureQueue::end_of_data() const
   {
   return (size() == 0);
   }

}
