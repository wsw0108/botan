/*
* Arithmetic for prime fields GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gfp_element.h>
#include <botan/numthry.h>
#include <botan/def_powm.h>
#include <botan/mp_types.h>
#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mem_ops.h>
#include <stdexcept>
#include <ostream>
#include <assert.h>

namespace Botan {

GFpElement::GFpElement(const BigInt& p, const BigInt& v) :
   modulus(p), value(v % p) {}

GFpElement::GFpElement(const GFpModulus& mod, const BigInt& v) :
   modulus(mod), value(v % mod.get_p()) {}

GFpElement& GFpElement::operator+=(const GFpElement& rhs)
   {
   value += rhs.value;
   value %= modulus.get_p();
   return *this;
   }

GFpElement& GFpElement::operator-=(const GFpElement& rhs)
   {
   value -= rhs.value;

   if(value.is_negative())
      value += modulus.get_p();

   return *this;
   }

GFpElement& GFpElement::operator*=(u32bit rhs)
   {
   value = (value * rhs) % modulus.get_p();
   return *this;
   }

GFpElement& GFpElement::operator*=(const GFpElement& rhs)
   {
   if(modulus != rhs.modulus)
      throw std::logic_error("Mismatched modulus in GFpElement *=");

   value = (value * rhs.value) % modulus.get_p();
   return *this;
   }

GFpElement& GFpElement::operator/=(const GFpElement& rhs)
   {
   GFpElement inv_rhs(rhs);
   inv_rhs.inverse_in_place();
   *this *= inv_rhs;
   return *this;
   }

GFpElement& GFpElement::inverse_in_place()
   {
   value = inverse_mod(value, modulus.get_p());
   return *this;
   }

GFpElement& GFpElement::negate()
   {
   value = modulus.get_p() - value;
   return *this;
   }

void GFpElement::swap(GFpElement& other)
   {
   modulus.swap(other.modulus);
   value.swap(other.value);
   }

std::ostream& operator<<(std::ostream& output, const GFpElement& elem)
   {
   return output << '(' << elem.get_value() << "," << elem.get_p() << ')';
   }

bool operator==(const GFpElement& lhs, const GFpElement& rhs)
   {
   if(lhs.get_p() != rhs.get_p())
      return false;

   if(lhs.get_value() != rhs.get_value())
      return false;

   return true;
   }

GFpElement operator+(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result += rhs;
   return result;
   }

GFpElement operator-(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result -= rhs;
   return result;
   // NOTE: the rhs might be transformed when using op-, the lhs never
   }

GFpElement operator-(const GFpElement& lhs)
   {
   return(GFpElement(lhs)).negate();
   }

GFpElement operator*(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result *= rhs;
   return result;
   }

GFpElement operator*(const GFpElement& lhs, u32bit rhs)
   {
   GFpElement result(lhs);
   result *= rhs;
   return result;
   }

GFpElement operator*(u32bit lhs, const GFpElement& rhs)
   {
   return rhs*lhs;
   }

GFpElement operator/(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result (lhs);
   result /= rhs;
   return result;
   }

SecureVector<byte> FE2OSP(const GFpElement& elem)
   {
   return BigInt::encode_1363(elem.get_value(), elem.get_p().bytes());
   }

GFpElement OS2FEP(MemoryRegion<byte> const& os, BigInt p)
   {
   return GFpElement(p, BigInt::decode(os.begin(), os.size()));
   }

GFpElement inverse(const GFpElement& elem)
   {
   return GFpElement(elem).inverse_in_place();
   }

}

