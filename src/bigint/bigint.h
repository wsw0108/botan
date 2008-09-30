/*************************************************
* BigInt Header File                             *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BIGINT_H__
#define BOTAN_BIGINT_H__

#include <botan/rng.h>
#include <botan/secmem.h>
#include <botan/mp_types.h>
#include <iosfwd>

namespace Botan {

/*************************************************
* BigInt                                         *
*************************************************/
class BOTAN_DLL BigInt
   {
   public:
      enum Base { Octal = 8, Decimal = 10, Hexadecimal = 16, Binary = 256 };
      enum Sign { Negative = 0, Positive = 1 };
      enum NumberType { Power2 };

      struct DivideByZero : public Exception
         { DivideByZero() : Exception("BigInt divide by zero") {} };

      BigInt& operator+=(const BigInt&);
      BigInt& operator-=(const BigInt&);

      BigInt& operator*=(const BigInt&);
      BigInt& operator/=(const BigInt&);
      BigInt& operator%=(const BigInt&);
      word    operator%=(word);
      BigInt& operator<<=(length_type);
      BigInt& operator>>=(length_type);

      BigInt& operator++() { return (*this += 1); }
      BigInt& operator--() { return (*this -= 1); }
      BigInt  operator++(int) { BigInt x = (*this); ++(*this); return x; }
      BigInt  operator--(int) { BigInt x = (*this); --(*this); return x; }

      BigInt operator-() const;
      bool operator !() const { return (!is_nonzero()); }

      s32bit cmp(const BigInt&, bool = true) const;
      bool is_even() const { return (get_bit(0) == 0); }
      bool is_odd()  const { return (get_bit(0) == 1); }

      bool is_zero() const
         {
         const length_type sw = sig_words();

         for(length_type i = 0; i != sw; ++i)
            if(reg[i])
               return false;
         return true;
         }

      bool is_nonzero() const { return (!is_zero()); }

      void set_bit(length_type);
      void clear_bit(length_type);
      void mask_bits(length_type);

      bool get_bit(length_type) const;
      u32bit get_substring(u32bit, u32bit) const;
      byte byte_at(length_type) const;

      // same as operator[], remove this
      word word_at(length_type n) const
         { return ((n < size()) ? get_reg()[n] : 0); }

      u32bit to_u32bit() const;

      bool is_negative() const { return (sign() == Negative); }
      bool is_positive() const { return (sign() == Positive); }
      Sign sign() const { return (signedness); }
      Sign reverse_sign() const;
      void flip_sign();
      void set_sign(Sign);
      BigInt abs() const;

      length_type size() const { return get_reg().size(); }

      length_type sig_words() const
         {
         const word* x = reg.begin();
         length_type sig = reg.size();

         while(sig && (x[sig-1] == 0))
            sig--;
         return sig;
         }

      length_type bytes() const;
      length_type bits() const;

      const word* data() const { return reg.begin(); }
      SecureVector<word>& get_reg() { return reg; }
      const SecureVector<word>& get_reg() const { return reg; }

      void grow_reg(length_type);
      void grow_to(length_type);

      word& operator[](length_type i) { return reg[i]; }
      word operator[](length_type i) const { return reg[i]; }
      void clear() { get_reg().clear(); }

      void randomize(RandomNumberGenerator& rng, length_type n);

      void binary_encode(byte[]) const;
      void binary_decode(const byte[], length_type);
      void binary_decode(const MemoryRegion<byte>&);
      length_type encoded_size(Base = Binary) const;

      static BigInt random_integer(RandomNumberGenerator&,
                                   const BigInt&, const BigInt&);

      static SecureVector<byte> encode(const BigInt&, Base = Binary);
      static void encode(byte[], const BigInt&, Base = Binary);
      static BigInt decode(const byte[], length_type, Base = Binary);
      static BigInt decode(const MemoryRegion<byte>&, Base = Binary);
      static SecureVector<byte> encode_1363(const BigInt&, length_type);

      void swap(BigInt&);

      BigInt() { signedness = Positive; }
      BigInt(u64bit);
      BigInt(const BigInt&);
      BigInt(const std::string&);
      BigInt(const byte[], length_type, Base = Binary);
      BigInt(RandomNumberGenerator& rng, length_type bits);
      BigInt(Sign, length_type);
      BigInt(NumberType, length_type);
   private:
      SecureVector<word> reg;
      Sign signedness;
   };

/*************************************************
* Arithmetic Operators                           *
*************************************************/
BigInt BOTAN_DLL operator+(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator-(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator*(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator/(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator%(const BigInt&, const BigInt&);
word   BOTAN_DLL operator%(const BigInt&, word);
BigInt BOTAN_DLL operator<<(const BigInt&, length_type);
BigInt BOTAN_DLL operator>>(const BigInt&, length_type);

/*************************************************
* Comparison Operators                           *
*************************************************/
inline bool operator==(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) == 0); }
inline bool operator!=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) != 0); }
inline bool operator<=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) <= 0); }
inline bool operator>=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) >= 0); }
inline bool operator<(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) < 0); }
inline bool operator>(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) > 0); }

/*************************************************
* I/O Operators                                  *
*************************************************/
BOTAN_DLL std::ostream& operator<<(std::ostream&, const BigInt&);
BOTAN_DLL std::istream& operator>>(std::istream&, BigInt&);

}

namespace std {

inline void swap(Botan::BigInt& a, Botan::BigInt& b) { a.swap(b); }

}

#endif
