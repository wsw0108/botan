/*************************************************
* EAX Mode Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EAX_H__
#define BOTAN_EAX_H__

#include <botan/basefilt.h>

namespace Botan {

/*************************************************
* EAX Base Class                                 *
*************************************************/
class BOTAN_DLL EAX_Base : public Keyed_Filter
   {
   public:
      void set_key(const SymmetricKey&);
      void set_iv(const InitializationVector&);
      void set_header(const byte[], length_type);
      std::string name() const;

      bool valid_keylength(length_type) const;

      ~EAX_Base() { delete cipher; delete mac; }
   protected:
      EAX_Base(const std::string&, length_type);
      void start_msg();
      void increment_counter();

      const length_type TAG_SIZE, BLOCK_SIZE;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;
      SecureVector<byte> nonce_mac, header_mac, state, buffer;
      length_type position;
   };

/*************************************************
* EAX Encryption                                 *
*************************************************/
class BOTAN_DLL EAX_Encryption : public EAX_Base
   {
   public:
      EAX_Encryption(const std::string&, length_type = 0);
      EAX_Encryption(const std::string&, const SymmetricKey&,
                     const InitializationVector&, length_type = 0);
   private:
      void write(const byte[], length_type);
      void end_msg();
   };

/*************************************************
* EAX Decryption                                 *
*************************************************/
class BOTAN_DLL EAX_Decryption : public EAX_Base
   {
   public:
      EAX_Decryption(const std::string&, length_type = 0);
      EAX_Decryption(const std::string&, const SymmetricKey&,
                     const InitializationVector&, length_type = 0);
   private:
      void write(const byte[], length_type);
      void do_write(const byte[], length_type);
      void end_msg();
      SecureVector<byte> queue;
      length_type queue_start, queue_end;
   };

}

#endif
