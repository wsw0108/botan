/*************************************************
* Randpool Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RANDPOOL_H__
#define BOTAN_RANDPOOL_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Randpool                                       *
*************************************************/
class BOTAN_DLL Randpool : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], length_type) throw(PRNG_Unseeded);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      Randpool();
      ~Randpool();
   private:
      void add_randomness(const byte[], length_type);
      void update_buffer();
      void mix_pool();

      const length_type ITERATIONS_BEFORE_RESEED, POOL_BLOCKS;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;

      SecureVector<byte> pool, buffer, counter;
      length_type entropy;
   };

}

#endif
