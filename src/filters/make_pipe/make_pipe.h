/*
* Create a Pipe
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MAKE_PIPE_H__
#define BOTAN_MAKE_PIPE_H__

#include <botan/pipe.h>

namespace Botan {

BOTAN_DLL Pipe* make_pipe(const std::string& filter_spec);

}

#endif
