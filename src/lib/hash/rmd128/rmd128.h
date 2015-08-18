/*
* RIPEMD-128
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RIPEMD_128_H__
#define BOTAN_RIPEMD_128_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* RIPEMD-128
*/
class BOTAN_DLL RIPEMD_128 : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "RIPEMD-128"; }
      size_t output_length() const override { return 16; }
      HashFunction* clone() const override { return new RIPEMD_128; }

      void clear() override;

      RIPEMD_128() : MDx_HashFunction(64, false, true), M(16), digest(4)
         { clear(); }
   private:
      void compress_n(const byte[], size_t blocks) override;
      void copy_out(byte[]) override;

      secure_vector<u32bit> M, digest;
   };

}

#endif
