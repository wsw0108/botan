/*************************************************
* ANSI X9.31 RNG Header File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ANSI_X931_RNG_H__
#define BOTAN_ANSI_X931_RNG_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* ANSI X9.31 RNG                                 *
*************************************************/
class BOTAN_DLL ANSI_X931_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], length_type) throw(PRNG_Unseeded);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      ANSI_X931_RNG(const std::string& = "", RandomNumberGenerator* = 0);
      ~ANSI_X931_RNG();
   private:
      void add_randomness(const byte[], length_type);
      void update_buffer();

      BlockCipher* cipher;
      RandomNumberGenerator* prng;
      SecureVector<byte> V, R;
      length_type position;
   };

}

#endif
