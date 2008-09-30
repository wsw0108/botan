/*************************************************
* Pooling Allocator Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_POOLING_ALLOCATOR_H__
#define BOTAN_POOLING_ALLOCATOR_H__

#include <botan/allocate.h>
#include <botan/exceptn.h>
#include <botan/mutex.h>
#include <utility>
#include <vector>

namespace Botan {

/*************************************************
* Pooling Allocator                              *
*************************************************/
class BOTAN_DLL Pooling_Allocator : public Allocator
   {
   public:
      void* allocate(length_type);
      void deallocate(void*, length_type);

      void destroy();

      Pooling_Allocator(Mutex*);
      ~Pooling_Allocator();
   private:
      void get_more_core(length_type);
      byte* allocate_blocks(length_type);

      virtual void* alloc_block(length_type) = 0;
      virtual void dealloc_block(void*, length_type) = 0;

      class BOTAN_DLL Memory_Block
         {
         public:
            Memory_Block(void*);

            static length_type bitmap_size() { return BITMAP_SIZE; }
            static length_type block_size() { return BLOCK_SIZE; }

            bool contains(void*, length_type) const throw();
            byte* alloc(length_type) throw();
            void free(void*, length_type) throw();

            bool operator<(const Memory_Block& other) const
               {
               if(buffer < other.buffer && other.buffer < buffer_end)
                  return false;
               return (buffer < other.buffer);
               }
         private:
            typedef u64bit bitmap_type;
            static const length_type BITMAP_SIZE = 8 * sizeof(bitmap_type);
            static const length_type BLOCK_SIZE = 64;

            bitmap_type bitmap;
            byte* buffer, *buffer_end;
         };

      static const length_type PREF_SIZE = BOTAN_MEM_POOL_CHUNK_SIZE;

      std::vector<Memory_Block> blocks;
      std::vector<Memory_Block>::iterator last_used;
      std::vector<std::pair<void*, length_type> > allocated;
      Mutex* mutex;
   };

}

#endif
