/*************************************************
* OpenSSL BN Wrapper Header File                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EXT_OPENSSL_BN_WRAP_H__
#define BOTAN_EXT_OPENSSL_BN_WRAP_H__

#include <botan/bigint.h>
#include <openssl/bn.h>

namespace Botan {

/*************************************************
* Lightweight OpenSSL BN Wrapper                 *
*************************************************/
class OSSL_BN
   {
   public:
      BIGNUM* value;

      BigInt to_bigint() const;
      void encode(byte[], length_type) const;
      length_type bytes() const;

      OSSL_BN& operator=(const OSSL_BN&);

      OSSL_BN(const OSSL_BN&);
      OSSL_BN(const BigInt& = 0);
      OSSL_BN(const byte[], length_type);
      ~OSSL_BN();
   };

/*************************************************
* Lightweight OpenSSL BN_CTX Wrapper             *
*************************************************/
class OSSL_BN_CTX
   {
   public:
      BN_CTX* value;

      OSSL_BN_CTX& operator=(const OSSL_BN_CTX&);

      OSSL_BN_CTX();
      OSSL_BN_CTX(const OSSL_BN_CTX&);
      ~OSSL_BN_CTX();
   };

}

#endif
