/*************************************************
* PK Utility Classes Header File                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PUBKEY_UTIL_H__
#define BOTAN_PUBKEY_UTIL_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Encoding Method for Encryption                 *
*************************************************/
class BOTAN_DLL EME
   {
   public:
      virtual length_type maximum_input_size(length_type) const = 0;

      SecureVector<byte> encode(const byte[], length_type, length_type) const;
      SecureVector<byte> encode(const MemoryRegion<byte>&, length_type) const;
      SecureVector<byte> decode(const byte[], length_type, length_type) const;
      SecureVector<byte> decode(const MemoryRegion<byte>&, length_type) const;

      virtual ~EME() {}
   private:
      virtual SecureVector<byte> pad(const byte[], length_type,
                                     length_type) const = 0;
      virtual SecureVector<byte> unpad(const byte[], length_type,
                                       length_type) const = 0;
   };

/*************************************************
* Encoding Method for Signatures, Appendix       *
*************************************************/
class BOTAN_DLL EMSA
   {
   public:
      virtual void update(const byte[], length_type) = 0;
      virtual SecureVector<byte> raw_data() = 0;

      virtual SecureVector<byte> encoding_of(const MemoryRegion<byte>&,
                                             length_type) = 0;

      virtual bool verify(const MemoryRegion<byte>&,
                          const MemoryRegion<byte>&,
                          length_type) throw();
      virtual ~EMSA() {}
   };

/*************************************************
* Key Derivation Function                        *
*************************************************/
class BOTAN_DLL KDF
   {
   public:
      SecureVector<byte> derive_key(length_type,
                                    const MemoryRegion<byte>&,
                                    const std::string& = "") const;

      SecureVector<byte> derive_key(length_type,
                                    const MemoryRegion<byte>&,
                                    const MemoryRegion<byte>&) const;

      SecureVector<byte> derive_key(length_type,
                                    const MemoryRegion<byte>&,
                                    const byte[], length_type) const;

      SecureVector<byte> derive_key(length_type,
                                    const byte[], length_type,
                                    const std::string& = "") const;

      SecureVector<byte> derive_key(length_type, const byte[], length_type,
                                    const byte[], length_type) const;

      virtual ~KDF() {}
   private:
      virtual SecureVector<byte> derive(length_type,
                                        const byte[], length_type,
                                        const byte[], length_type) const = 0;
   };

/*************************************************
* Mask Generation Function                       *
*************************************************/
class BOTAN_DLL MGF
   {
   public:
      virtual void mask(const byte[], length_type,
                        byte[], length_type) const = 0;
      virtual ~MGF() {}
   };

}

#endif
