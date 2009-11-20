/*
* GF(p) modulus class
*
* (C) 2008 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_MODULUS_H__
#define BOTAN_GFP_MODULUS_H__

#include <botan/bigint.h>

namespace Botan {

/**
* This class represents a GFpElement modulus including the modulus
* related values necessary for the montgomery multiplication.
*/
class BOTAN_DLL GFpModulus
   {
   public:
      /**
      * Construct a GF(P)-Modulus from a BigInt
      */
      GFpModulus(const BigInt& p);

      // default cp-ctor, operator= are fine

      /**
      * Tells whether the precomputations necessary for the use of the
      * montgomery multiplication have yet been established.
      * @result true if the precomputated value are already available.
      */
      inline bool has_precomputations() const
         {
         return true; // FIXME: remove
         }

      /**
      * Swaps this with another GFpModulus, does not throw.
      * @param other the GFpModulus to swap *this with.
      */
      inline void swap(GFpModulus& other)
         {
         p.swap(other.p);
         p_dash.swap(other.p_dash);
         r.swap(other.r);
         r_inv.swap(other.r_inv);
         }

      /**
      * The other member values depend only on p
      */
      bool operator==(const GFpModulus& other) const
         {
         return (get_p() == other.get_p());
         }

      /**
      * The other member values depend only on p
      */
      bool operator!=(const GFpModulus& other) const
         {
         return (get_p() != other.get_p());
         }

      /**
      * Return the modulus of this GFpModulus.
      * @result the modulus of *this.
      */
      inline const BigInt& get_p() const
         {
         return p;
         }

      /**
      * returns the montgomery multiplication related value r.
      * @result r
      */
      inline const BigInt& get_r() const
         {
         return r;
         }

      /**
      * returns the montgomery multiplication related value r^{-1}.
      * @result r^{-1}
      */
      inline const BigInt& get_r_inv() const
         {
         return r_inv;
         }

      /**
      * returns the montgomery multiplication related value p'.
      * @result p'
      */
      inline const BigInt& get_p_dash() const
         {
         return p_dash;
         }

   private:
      BigInt p; // the modulus itself
      BigInt p_dash;
      BigInt r;
      BigInt r_inv;
   };

}

#endif
