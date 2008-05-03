/*************************************************
* Lion Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_LION_H__
#define BOTAN_LION_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Lion                                           *
*************************************************/
class BOTAN_DLL Lion : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      BlockCipher* clone() const;
      Lion(const std::string&, const std::string&, length_type);
      ~Lion() { delete hash; delete cipher; }
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], length_type);
      const length_type LEFT_SIZE, RIGHT_SIZE;
      HashFunction* hash;
      StreamCipher* cipher;
      SecureVector<byte> key1, key2;
   };

}

#endif
