/*************************************************
* CFB Mode Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CFB_H__
#define BOTAN_CFB_H__

#include <botan/modebase.h>

namespace Botan {

/*************************************************
* CFB Encryption                                 *
*************************************************/
class BOTAN_DLL CFB_Encryption : public BlockCipherMode
   {
   public:
      CFB_Encryption(const std::string&, length_type = 0);
      CFB_Encryption(const std::string&, const SymmetricKey&,
                     const InitializationVector&, length_type = 0);
   private:
      void write(const byte[], length_type);
      void feedback();
      const length_type FEEDBACK_SIZE;
   };

/*************************************************
* CFB Decryption                                 *
*************************************************/
class BOTAN_DLL CFB_Decryption : public BlockCipherMode
   {
   public:
      CFB_Decryption(const std::string&, length_type = 0);
      CFB_Decryption(const std::string&, const SymmetricKey&,
                     const InitializationVector&, length_type = 0);
   private:
      void write(const byte[], length_type);
      void feedback();
      const length_type FEEDBACK_SIZE;
   };

}

#endif
