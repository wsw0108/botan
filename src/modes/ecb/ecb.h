/*************************************************
* ECB Mode Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ECB_H__
#define BOTAN_ECB_H__

#include <botan/modebase.h>
#include <botan/mode_pad.h>

namespace Botan {

/*************************************************
* ECB                                            *
*************************************************/
class BOTAN_DLL ECB : public BlockCipherMode
   {
   protected:
      ECB(const std::string&, const std::string&);
      std::string name() const;
      const BlockCipherModePaddingMethod* padder;
   private:
      bool valid_iv_size(length_type) const;
   };

/*************************************************
* ECB Encryption                                 *
*************************************************/
class BOTAN_DLL ECB_Encryption : public ECB
   {
   public:
      ECB_Encryption(const std::string&, const std::string&);
      ECB_Encryption(const std::string&, const std::string&,
                     const SymmetricKey&);
   private:
      void write(const byte[], length_type);
      void end_msg();
   };

/*************************************************
* ECB Decryption                                 *
*************************************************/
class BOTAN_DLL ECB_Decryption : public ECB
   {
   public:
      ECB_Decryption(const std::string&, const std::string&);
      ECB_Decryption(const std::string&, const std::string&,
                     const SymmetricKey&);
   private:
      void write(const byte[], length_type);
      void end_msg();
   };

}

#endif
