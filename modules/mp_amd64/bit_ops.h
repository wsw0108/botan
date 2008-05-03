/*************************************************
* Bit/Word Operations Header File                *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BIT_OPS_H__
#define BOTAN_BIT_OPS_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* Word Rotation Functions                        *
*************************************************/
template<typename T> inline T rotate_left(T input, length_type rot)
   {
   return static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot)));;
   }

template<typename T> inline T rotate_right(T input, length_type rot)
   {
   return static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot)));
   }

/*************************************************
* Byte Swapping Functions                        *
*************************************************/
inline u16bit reverse_bytes(u16bit input)
   {
   return rotate_left(input, 8);
   }

inline u32bit reverse_bytes(u32bit input)
   {
   asm("bswapl %0" : "=r" (input) : "0" (input));
   return input;
   }

inline u64bit reverse_bytes(u64bit input)
   {
   asm("bswapq %0" : "=r" (input) : "0" (input));
   return input;
   }

/*************************************************
* XOR Arrays                                     *
*************************************************/
inline void xor_buf(byte out[], const byte in[], length_type length)
   {
   while(length >= 8)
      {
      *reinterpret_cast<u64bit*>(out) ^= *reinterpret_cast<const u64bit*>(in);
      in += 8; out += 8; length -= 8;
      }

   for(length_type j = 0; j != length; ++j)
      out[j] ^= in[j];
   }

/*************************************************
* XOR Arrays                                     *
*************************************************/
inline void xor_buf(byte out[], const byte in[],
                    const byte in2[], length_type length)
   {
   while(length >= 8)
      {
      *reinterpret_cast<u64bit*>(out) =
         *reinterpret_cast<const u64bit*>(in) ^
         *reinterpret_cast<const u64bit*>(in2);

      in += 8; in2 += 8; out += 8; length -= 8;
      }

   for(length_type j = 0; j != length; ++j)
      out[j] = in[j] ^ in2[j];
   }

/*************************************************
* Simple Bit Manipulation                        *
*************************************************/
bool power_of_2(u64bit);
length_type high_bit(u64bit);
length_type low_bit(u64bit);
length_type significant_bytes(u64bit);
length_type hamming_weight(u64bit);

}

#endif
