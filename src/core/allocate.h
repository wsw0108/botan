/*************************************************
* Allocator Header File                          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ALLOCATOR_H__
#define BOTAN_ALLOCATOR_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/*************************************************
* Allocator Interface                            *
*************************************************/
class BOTAN_DLL Allocator
   {
   public:
      static Allocator* get(bool);

      virtual void* allocate(length_type) = 0;
      virtual void deallocate(void*, length_type) = 0;

      virtual std::string type() const = 0;

      virtual void init() {}
      virtual void destroy() {}

      virtual ~Allocator() {}
   };

}

#endif
