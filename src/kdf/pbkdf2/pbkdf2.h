/*************************************************
* PBKDF2 Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PBKDF2_H__
#define BOTAN_PBKDF2_H__

#include <botan/s2k.h>
#include <botan/base.h>

namespace Botan {

/*************************************************
* PKCS #5 PBKDF2                                 *
*************************************************/
class BOTAN_DLL PKCS5_PBKDF2 : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;

      PKCS5_PBKDF2(MessageAuthenticationCode* m);
      ~PKCS5_PBKDF2();
   private:
      OctetString derive(length_type, const std::string&,
                          const byte[], length_type, length_type) const;

      MessageAuthenticationCode* mac;
   };

}

#endif
