/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/curve_gfp.h>
#include <botan/bigint.h>
#include <stdexcept>
#include <ostream>

namespace Botan {

CurveGFp::CurveGFp(const GFpElement& a, const GFpElement& b,
                   const BigInt& p) : modulus(p), mA(a), mB(b)
   {
   if(p != mA.get_p() || p != mB.get_p())
      throw Invalid_Argument("CurveGFp: moduli of arguments differ");
   }

// swaps the states of *this and other, does not throw
void CurveGFp::swap(CurveGFp& other)
   {
   mA.swap(other.mA);
   mB.swap(other.mB);
   modulus.swap(other.modulus);
   }

bool operator==(const CurveGFp& lhs, const CurveGFp& rhs)
   {
   if(lhs.get_modulus() != rhs.get_modulus())
      return false;
   if(lhs.get_a() != rhs.get_a())
      return false;
   if(lhs.get_b() != rhs.get_b())
      return false;

   return true;
   }

std::ostream& operator<<(std::ostream& output, const CurveGFp& elem)
   {
   return output << "y^2f = x^3 + (" << elem.get_a() << ")x + (" << elem.get_b() << ")";
   }

}
