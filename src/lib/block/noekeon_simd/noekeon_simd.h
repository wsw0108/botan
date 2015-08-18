/*
* Noekeon in SIMD
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_NOEKEON_SIMD_H__
#define BOTAN_NOEKEON_SIMD_H__

#include <botan/noekeon.h>

namespace Botan {

/**
* Noekeon implementation using SIMD operations
*/
class BOTAN_DLL Noekeon_SIMD : public Noekeon
   {
   public:
      size_t parallelism() const override { return 4; }

      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const override;

      BlockCipher* clone() const override { return new Noekeon_SIMD; }
   };

}

#endif
