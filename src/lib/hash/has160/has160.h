/*
* HAS-160
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HAS_160_H__
#define BOTAN_HAS_160_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* HAS-160, a Korean hash function standardized in
* TTAS.KO-12.0011/R1. Used in conjunction with KCDSA
*/
class BOTAN_DLL HAS_160 : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "HAS-160"; }
      size_t output_length() const override { return 20; }
      HashFunction* clone() const override { return new HAS_160; }

      void clear() override;

      HAS_160() : MDx_HashFunction(64, false, true), X(20), digest(5)
         { clear(); }
   private:
      void compress_n(const byte[], size_t blocks) override;
      void copy_out(byte[]) override;

      secure_vector<u32bit> X, digest;
   };

}

#endif
