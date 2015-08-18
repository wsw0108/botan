/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_IDEA_H__
#define BOTAN_IDEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* IDEA
*/
class BOTAN_DLL IDEA : public Block_Cipher_Fixed_Params<8, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const override;

      void clear() override;
      std::string name() const override { return "IDEA"; }
      BlockCipher* clone() const override { return new IDEA; }
   protected:
      /**
      * @return const reference to encryption subkeys
      */
      const secure_vector<u16bit>& get_EK() const { return EK; }

      /**
      * @return const reference to decryption subkeys
      */
      const secure_vector<u16bit>& get_DK() const { return DK; }

   private:
      void key_schedule(const byte[], size_t) override;

      secure_vector<u16bit> EK, DK;
   };

}

#endif
