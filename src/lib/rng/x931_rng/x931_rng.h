/*
* ANSI X9.31 RNG
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ANSI_X931_RNG_H__
#define BOTAN_ANSI_X931_RNG_H__

#include <botan/rng.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* ANSI X9.31 RNG
*/
class BOTAN_DLL ANSI_X931_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], size_t) override;
      bool is_seeded() const override;
      void clear() override;
      std::string name() const override;

      void reseed(size_t poll_bits) override;
      void add_entropy(const byte[], size_t) override;

      /**
      * @param cipher the block cipher to use in this PRNG
      * @param rng the underlying PRNG for generating inputs
      * (eg, an HMAC_RNG)
      */
      ANSI_X931_RNG(BlockCipher* cipher,
                    RandomNumberGenerator* rng);

   private:
      void rekey();
      void update_buffer();

      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<RandomNumberGenerator> m_prng;
      secure_vector<byte> m_V, m_R;
      size_t m_R_pos;
   };

}

#endif
