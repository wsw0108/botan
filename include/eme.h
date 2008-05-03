/*************************************************
* EME Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EME_H__
#define BOTAN_EME_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* EME1                                           *
*************************************************/
class BOTAN_DLL EME1 : public EME
   {
   public:
      length_type maximum_input_size(length_type) const;

      EME1(const std::string&, const std::string&, const std::string& = "");
      ~EME1() { delete mgf; }
   private:
      SecureVector<byte> pad(const byte[], length_type, length_type) const;
      SecureVector<byte> unpad(const byte[], length_type, length_type) const;
      const length_type HASH_LENGTH;
      SecureVector<byte> Phash;
      MGF* mgf;
   };

/*************************************************
* EME_PKCS1v15                                   *
*************************************************/
class BOTAN_DLL EME_PKCS1v15 : public EME
   {
   public:
      length_type maximum_input_size(length_type) const;
   private:
      SecureVector<byte> pad(const byte[], length_type, length_type) const;
      SecureVector<byte> unpad(const byte[], length_type, length_type) const;
   };

}

#endif
