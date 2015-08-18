/*
* Win32 EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_WIN32_H__
#define BOTAN_ENTROPY_SRC_WIN32_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* Win32 Entropy Source
*/
class Win32_EntropySource : public EntropySource
   {
   public:
      std::string name() const override { return "Win32 Statistics"; }
      void poll(Entropy_Accumulator& accum) override;
   };

}

#endif
