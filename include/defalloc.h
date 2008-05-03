/*************************************************
* Basic Allocators Header File                   *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BASIC_ALLOC_H__
#define BOTAN_BASIC_ALLOC_H__

#include <botan/mem_pool.h>

namespace Botan {

/*************************************************
* Malloc Allocator                              *
*************************************************/
class BOTAN_DLL Malloc_Allocator : public Allocator
   {
   public:
      void* allocate(length_type);
      void deallocate(void*, length_type);

      std::string type() const { return "malloc"; }
   };

/*************************************************
* Locking Allocator                              *
*************************************************/
class BOTAN_DLL Locking_Allocator : public Pooling_Allocator
   {
   public:
      std::string type() const { return "locking"; }
   private:
      void* alloc_block(length_type);
      void dealloc_block(void*, length_type);
   };

}

#endif
