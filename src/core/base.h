/*************************************************
* Base Classes Header File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BASE_H__
#define BOTAN_BASE_H__

#include <botan/exceptn.h>
#include <botan/symkey.h>

namespace Botan {

/*************************************************
* Constants                                      *
*************************************************/
static const length_type DEFAULT_BUFFERSIZE = BOTAN_DEFAULT_BUFFER_SIZE;

/*************************************************
* Symmetric Algorithm                            *
*************************************************/
class BOTAN_DLL SymmetricAlgorithm
   {
   public:
      const length_type MAXIMUM_KEYLENGTH,
                        MINIMUM_KEYLENGTH,
                        KEYLENGTH_MULTIPLE;

      virtual std::string name() const = 0;

      void set_key(const SymmetricKey&) throw(Invalid_Key_Length);
      void set_key(const byte[], length_type) throw(Invalid_Key_Length);
      bool valid_keylength(length_type) const;

      SymmetricAlgorithm(length_type, length_type, length_type);
      virtual ~SymmetricAlgorithm() {}
   private:
      virtual void key(const byte[], length_type) = 0;
   };

/*************************************************
* Block Cipher                                   *
*************************************************/
class BOTAN_DLL BlockCipher : public SymmetricAlgorithm
   {
   public:
      const length_type BLOCK_SIZE;

      void encrypt(const byte in[], byte out[]) const { enc(in, out); }
      void decrypt(const byte in[], byte out[]) const { dec(in, out); }
      void encrypt(byte block[]) const { enc(block, block); }
      void decrypt(byte block[]) const { dec(block, block); }

      virtual BlockCipher* clone() const = 0;
      virtual void clear() throw() = 0;

      BlockCipher(length_type, length_type, length_type = 0, length_type = 1);
      virtual ~BlockCipher() {}
   private:
      virtual void enc(const byte[], byte[]) const = 0;
      virtual void dec(const byte[], byte[]) const = 0;
   };

/*************************************************
* Stream Cipher                                  *
*************************************************/
class BOTAN_DLL StreamCipher : public SymmetricAlgorithm
   {
   public:
      const length_type IV_LENGTH;

      void encrypt(const byte in[], byte out[], length_type length)
         { cipher(in, out, length); }
      void decrypt(const byte in[], byte out[], length_type length)
         { cipher(in, out, length); }

      void encrypt(byte in[], length_type length) { cipher(in, in, length); }
      void decrypt(byte in[], length_type length) { cipher(in, in, length); }

      virtual void resync(const byte[], length_type);
      virtual void seek(length_type);

      virtual StreamCipher* clone() const = 0;
      virtual void clear() throw() = 0;

      StreamCipher(length_type, length_type = 0,
                   length_type = 1, length_type = 0);
      virtual ~StreamCipher() {}
   private:
      virtual void cipher(const byte[], byte[], length_type) = 0;
   };

/*************************************************
* Buffered Computation                           *
*************************************************/
class BOTAN_DLL BufferedComputation
   {
   public:
      const length_type OUTPUT_LENGTH;

      void update(const byte[], length_type);
      void update(const MemoryRegion<byte>&);
      void update(const std::string&);
      void update(byte);

      void final(byte out[]) { final_result(out); }
      SecureVector<byte> final();
      SecureVector<byte> process(const byte[], u32bit);
      SecureVector<byte> process(const MemoryRegion<byte>&);
      SecureVector<byte> process(const std::string&);

      BufferedComputation(length_type);
      virtual ~BufferedComputation() {}
   private:
      BufferedComputation& operator=(const BufferedComputation&);
      virtual void add_data(const byte[], length_type) = 0;
      virtual void final_result(byte[]) = 0;
   };

/*************************************************
* Hash Function                                  *
*************************************************/
class BOTAN_DLL HashFunction : public BufferedComputation
   {
   public:
      const length_type HASH_BLOCK_SIZE;

      virtual HashFunction* clone() const = 0;
      virtual std::string name() const = 0;
      virtual void clear() throw() = 0;

      HashFunction(length_type, length_type = 0);
      virtual ~HashFunction() {}
   private:
      HashFunction& operator=(const HashFunction&);
   };

/*************************************************
* Message Authentication Code                    *
*************************************************/
class BOTAN_DLL MessageAuthenticationCode : public BufferedComputation,
                                  public SymmetricAlgorithm
   {
   public:
      virtual bool verify_mac(const byte[], length_type);

      virtual MessageAuthenticationCode* clone() const = 0;
      virtual std::string name() const = 0;
      virtual void clear() throw() = 0;

      MessageAuthenticationCode(length_type, length_type,
                                length_type = 0, length_type = 1);
      virtual ~MessageAuthenticationCode() {}
   };

}

#endif
