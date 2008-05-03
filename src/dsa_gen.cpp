/*************************************************
* DSA Parameter Generation Source File           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/dl_group.h>
#include <botan/numthry.h>
#include <botan/lookup.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <algorithm>
#include <memory>

namespace Botan {

namespace {

/*************************************************
* Check if this size is allowed by FIPS 186-3    *
*************************************************/
bool fips186_3_valid_size(length_type pbits, length_type qbits)
   {
   if(pbits == 1024 && qbits == 160)
      return true;
   if(pbits == 2048 && (qbits == 224 || qbits == 256))
      return true;
   if(pbits == 3072 && qbits == 256)
      return true;
   return false;
   }

}

/*************************************************
* Attempt DSA prime generation with given seed   *
*************************************************/
bool DL_Group::generate_dsa_primes(BigInt& p, BigInt& q,
                                   length_type pbits, length_type qbits,
                                   const MemoryRegion<byte>& seed_c)
   {
   if(!fips186_3_valid_size(pbits, qbits))
      throw Invalid_Argument(
         "FIPS 186-3 does not allow DSA domain parameters of " +
         to_string(pbits) + "/" + to_string(qbits) + " bits long");

   if(qbits == 224)
      throw Invalid_Argument(
         "DSA parameter generation with a q of 224 bits not supported");

   if(seed_c.size() * 8 < qbits)
      throw Invalid_Argument(
         "Generating a DSA parameter set with a " + to_string(qbits) +
         "long q requires a seed at least as many bits long");

   std::auto_ptr<HashFunction> hash(get_hash("SHA-" + to_string(qbits)));

   const length_type HASH_SIZE = hash->OUTPUT_LENGTH;

   class Seed
      {
      public:
         Seed(const MemoryRegion<byte>& s) : seed(s) {}

         operator MemoryRegion<byte>& () { return seed; }

         Seed& operator++()
            {
            for(length_type j = seed.size(); j > 0; --j)
               if(++seed[j-1])
                  break;
            return (*this);
            }
      private:
         SecureVector<byte> seed;
      };

   Seed seed(seed_c);

   q.binary_decode(hash->process(seed));
   q.set_bit(qbits-1);
   q.set_bit(0);

   if(!is_prime(q))
      return false;

   const length_type n = (pbits-1) / (HASH_SIZE * 8),
                     b = (pbits-1) % (HASH_SIZE * 8);

   BigInt X;
   SecureVector<byte> V(HASH_SIZE * (n+1));

   for(length_type j = 0; j != 4096; ++j)
      {
      for(length_type k = 0; k <= n; ++k)
         {
         ++seed;
         hash->update(seed);
         hash->final(V + HASH_SIZE * (n-k));
         }

      X.binary_decode(V + (HASH_SIZE - 1 - b/8),
                      V.size() - (HASH_SIZE - 1 - b/8));
      X.set_bit(pbits-1);

      p = X - (X % (2*q) - 1);

      if(p.bits() == pbits && is_prime(p))
         return true;
      }
   return false;
   }

/*************************************************
* Generate DSA Primes                            *
*************************************************/
SecureVector<byte> DL_Group::generate_dsa_primes(BigInt& p, BigInt& q,
                                                 length_type pbits,
                                                 length_type qbits)
   {
   SecureVector<byte> seed(qbits/8);

   while(true)
      {
      global_state().randomize(seed, seed.size());

      if(generate_dsa_primes(p, q, pbits, qbits, seed))
         return seed;
      }
   }

}
