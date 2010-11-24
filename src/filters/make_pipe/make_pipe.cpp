/*
* Create a Pipe
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/make_pipe.h>
#include <memory>

namespace Botan {

Pipe* make_pipe(const std::string& filter_spec)
   {
   std::auto_ptr<Pipe> result(new Pipe);

   return result.release();
   }

}
