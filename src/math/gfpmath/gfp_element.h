/*
* Arithmetic for prime fields GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_ELEMENT_H__
#define BOTAN_GFP_ELEMENT_H__

#include <botan/bigint.h>
#include <botan/gfp_modulus.h>
#include <iosfwd>

namespace Botan {

struct BOTAN_DLL Illegal_Transformation : public Exception
   {
   Illegal_Transformation(const std::string& err =
                          "Requested transformation is not possible") :
      Exception(err) {}
   };

/**
 * This class represents one element in GF(p). Enables the convenient,
 * transparent use of the montgomery multiplication.
 */
class BOTAN_DLL GFpElement
   {
   public:

      /** construct an element of GF(p) with the given value.
      * use_montg defaults to false and determines wether Montgomery
      * multiplications will be use when applying operators *, *=
      * @param p the prime number of the field
      * @param value the element value
      * @param use_montgm whether this object will use Montgomery multiplication
      */
      explicit GFpElement(const BigInt& p, const BigInt& value);

      /** construct an element of GF(p) with the given value
      * @param mod the GFpModulus
      * @param value the element value
      */
      explicit GFpElement(const GFpModulus& mod, const BigInt& value);

      // default cp-ctor, operator= are OK

      /**
      * += Operator
      * @param rhs the GFpElement to add to the local value
      * @result *this
      */
      GFpElement& operator+=(const GFpElement& rhs);

      /**
      * -= Operator
      * @param rhs the GFpElement to subtract from the local value
      * @result *this
      */
      GFpElement& operator-=(const GFpElement& rhs);

      /**
      * *= Operator
      * @param rhs the GFpElement to multiply with the local value
      * @result *this
      */
      GFpElement& operator*=(const GFpElement& rhs);

      /**
      * /= Operator
      * @param rhs the GFpElement to divide the local value by
      * @result *this
      */
      GFpElement& operator/=(const GFpElement& rhs);

      /**
      * *= Operator
      * @param rhs the value to multiply with the local value
      * @result *this
      */
      GFpElement& operator*=(u32bit rhs);

      /**
      * Negate internal value(*this *= -1 )
      * @return *this
      */
      GFpElement& negate();

      /**
      * Assigns the inverse of *this to *this, i.e.
      * *this = (*this)^(-1)
      * @result *this
      */
      GFpElement& inverse_in_place();

      /**
      * checks whether the value is zero (without provoking
      * a backtransformation to the ordinary-residue)
      * @result true, if the value is zero, false otherwise.
      */
      bool is_zero() const { return value.is_zero(); }

      /**
      * return prime number of GF(p)
      * @result a prime number
      */
      const BigInt& get_p() const { return modulus.get_p(); }

      /**
      * Return the represented value in GF(p)
      * @result The value in GF(p)
      */
      const BigInt& get_value() const { return value; }

      /**
      * write a GFpElement to an output stream.
      * @param output the output stream to write to
      * @param elem the object to write
      * @result the output stream
      */
      friend std::ostream& operator<<(std::ostream& output, const GFpElement& elem);

      /**
      * swaps the states of *this and other, does not throw!
      * @param other value to swap with
      */
      void swap(GFpElement& other);
   private:
      GFpModulus modulus;
      BigInt value;
   };

// relational operators
bool operator==(const GFpElement& lhs, const GFpElement& rhs);
inline bool operator!=(const GFpElement& lhs, const GFpElement& rhs )
   {
   return !operator==(lhs, rhs);
   }

// arithmetic operators
GFpElement operator+(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator-(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator-(const GFpElement& lhs);

GFpElement operator*(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator/(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator*(const GFpElement& lhs, u32bit rhs);
GFpElement operator*(u32bit rhs, const GFpElement& lhs);

// io operators
std::ostream& operator<<(std::ostream& output, const GFpElement& elem);

// return (*this)^(-1)
GFpElement inverse(const GFpElement& elem);

// encoding and decoding
SecureVector<byte> FE2OSP(const GFpElement& elem);
GFpElement OS2FEP(MemoryRegion<byte> const& os, BigInt p);

inline void swap(GFpElement& x, GFpElement& y)
   {
   x.swap(y);
   }

}

namespace std {

template<> inline
void swap<Botan::GFpElement>(Botan::GFpElement& x,
                             Botan::GFpElement& y)
   {
   x.swap(y);
   }

}

#endif
