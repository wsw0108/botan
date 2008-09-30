/*************************************************
* Block Cipher Mode Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MODEBASE_H__
#define BOTAN_MODEBASE_H__

#include <botan/basefilt.h>

namespace Botan {

/*************************************************
* Block Cipher Mode                              *
*************************************************/
class BOTAN_DLL BlockCipherMode : public Keyed_Filter
   {
   public:
      std::string name() const;

      BlockCipherMode(const std::string&, const std::string&,
                      length_type, length_type = 0, length_type = 1);
      virtual ~BlockCipherMode() { delete cipher; }
   protected:
      void set_iv(const InitializationVector&);
      const length_type BLOCK_SIZE, BUFFER_SIZE, IV_METHOD;
      const std::string mode_name;
      BlockCipher* cipher;
      SecureVector<byte> buffer, state;
      length_type position;
   };

}

#endif
