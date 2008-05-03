/*************************************************
* OpenPGP S2K Header File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_OPENPGP_S2K_H__
#define BOTAN_OPENPGP_S2K_H__

#include <botan/s2k.h>

namespace Botan {

/*************************************************
* OpenPGP S2K                                    *
*************************************************/
class BOTAN_DLL OpenPGP_S2K : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;
      OpenPGP_S2K(const std::string&);
   private:
      OctetString derive(length_type, const std::string&,
                         const byte[], length_type, length_type) const;
      const std::string hash_name;
   };

}

#endif
