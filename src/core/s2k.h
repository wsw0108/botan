/*************************************************
* S2K Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_S2K_H__
#define BOTAN_S2K_H__

#include <botan/symkey.h>
#include <botan/rng.h>

namespace Botan {

/*************************************************
* S2K Interface                                  *
*************************************************/
class BOTAN_DLL S2K
   {
   public:
      virtual S2K* clone() const = 0;
      virtual std::string name() const = 0;
      virtual void clear() {}

      OctetString derive_key(length_type, const std::string&) const;

      void set_iterations(length_type);
      void change_salt(const byte[], length_type);
      void change_salt(const MemoryRegion<byte>&);
      void new_random_salt(RandomNumberGenerator& rng, length_type);

      length_type iterations() const { return iter; }
      SecureVector<byte> current_salt() const { return salt; }

      S2K() { iter = 0; }
      virtual ~S2K() {}
   private:
      virtual OctetString derive(length_type, const std::string&,
                                 const byte[], length_type,
                                 length_type) const = 0;

      SecureVector<byte> salt;
      length_type iter;
   };

}

#endif
