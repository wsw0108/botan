/*************************************************
* MDx Hash Function Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MDX_BASE_H__
#define BOTAN_MDX_BASE_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* MDx Hash Function Base Class                   *
*************************************************/
class BOTAN_DLL MDx_HashFunction : public HashFunction
   {
   public:
      MDx_HashFunction(length_type, length_type, bool, bool, length_type = 8);
      virtual ~MDx_HashFunction() {}
   protected:
      void clear() throw();
      SecureVector<byte> buffer;
      u64bit count;
      length_type position;
   private:
      void add_data(const byte[], length_type);
      void final_result(byte output[]);

      virtual void hash(const byte[]) = 0;
      virtual void copy_out(byte[]) = 0;
      virtual void write_count(byte[]);

      const bool BIG_BYTE_ENDIAN, BIG_BIT_ENDIAN;
      const length_type COUNT_SIZE;
   };

}

#endif
