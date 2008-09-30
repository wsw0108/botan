/*************************************************
* Randpool Header File                           *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RANDPOOL_H__
#define BOTAN_RANDPOOL_H__

#include <botan/rng.h>
#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Randpool                                       *
*************************************************/
class BOTAN_DLL Randpool : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], length_type);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      void reseed();
      void add_entropy_source(EntropySource*);
      void add_entropy(const byte[], length_type);

      Randpool(BlockCipher*, MessageAuthenticationCode*,
               length_type pool_blocks = 32,
               length_type iterations_before_reseed = 128);

      ~Randpool();
   private:
      void update_buffer();
      void mix_pool();

      length_type ITERATIONS_BEFORE_RESEED, POOL_BLOCKS;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;

      std::vector<EntropySource*> entropy_sources;
      SecureVector<byte> pool, buffer, counter;
      length_type entropy;
   };

}

#endif
