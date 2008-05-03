/*************************************************
* CBC Padding Methods Header File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CBC_PADDING_H__
#define BOTAN_CBC_PADDING_H__

#include <botan/base.h>
#include <string>

namespace Botan {

/*************************************************
* Block Cipher Mode Padding Method               *
*************************************************/
class BOTAN_DLL BlockCipherModePaddingMethod
   {
   public:
      virtual void pad(byte[], length_type, length_type) const = 0;
      virtual length_type unpad(const byte[], length_type) const = 0;
      virtual length_type pad_bytes(length_type, length_type) const;
      virtual bool valid_blocksize(length_type) const = 0;
      virtual std::string name() const = 0;
      virtual ~BlockCipherModePaddingMethod() {}
   };

/*************************************************
* PKCS#7 Padding                                 *
*************************************************/
class BOTAN_DLL PKCS7_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], length_type, length_type) const;
      length_type unpad(const byte[], length_type) const;
      bool valid_blocksize(length_type) const;
      std::string name() const { return "PKCS7"; }
   };

/*************************************************
* ANSI X9.23 Padding                             *
*************************************************/
class BOTAN_DLL ANSI_X923_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], length_type, length_type) const;
      length_type unpad(const byte[], length_type) const;
      bool valid_blocksize(length_type) const;
      std::string name() const { return "X9.23"; }
   };

/*************************************************
* One And Zeros Padding                          *
*************************************************/
class BOTAN_DLL OneAndZeros_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], length_type, length_type) const;
      length_type unpad(const byte[], length_type) const;
      bool valid_blocksize(length_type) const;
      std::string name() const { return "OneAndZeros"; }
   };

/*************************************************
* Null Padding                                   *
*************************************************/
class BOTAN_DLL Null_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], length_type, length_type) const { return; }
      length_type unpad(const byte[], length_type size) const { return size; }
      length_type pad_bytes(length_type, length_type) const { return 0; }
      bool valid_blocksize(length_type) const { return true; }
      std::string name() const { return "NoPadding"; }
   };

}

#endif
