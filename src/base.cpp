/*************************************************
* Base Classes Source File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/base.h>
#include <botan/version.h>
#include <botan/util.h>
#include <botan/config.h>

namespace Botan {

/*************************************************
* SymmetricAlgorithm Constructor                 *
*************************************************/
SymmetricAlgorithm::SymmetricAlgorithm(length_type key_min,
                                       length_type key_max,
                                       length_type key_mod) :
   MAXIMUM_KEYLENGTH(key_max ? key_max : key_min),
   MINIMUM_KEYLENGTH(key_min),
   KEYLENGTH_MULTIPLE(key_mod)
   {
   }

/*************************************************
* Query if the keylength is valid                *
*************************************************/
bool SymmetricAlgorithm::valid_keylength(length_type length) const
   {
   return ((length >= MINIMUM_KEYLENGTH) &&
           (length <= MAXIMUM_KEYLENGTH) &&
           (length % KEYLENGTH_MULTIPLE == 0));
   }

/*************************************************
* Set the key                                    *
*************************************************/
void SymmetricAlgorithm::set_key(const SymmetricKey& algo_key)
   throw(Invalid_Key_Length)
   {
   set_key(algo_key.begin(), algo_key.length());
   }

/*************************************************
* Set the key                                    *
*************************************************/
void SymmetricAlgorithm::set_key(const byte algo_key[], length_type length)
   throw(Invalid_Key_Length)
   {
   if(!valid_keylength(length))
      throw Invalid_Key_Length(name(), length);
   key(algo_key, length);
   }

/*************************************************
* BlockCipher Constructor                        *
*************************************************/
BlockCipher::BlockCipher(length_type block, length_type key_min,
                         length_type key_max,
                         length_type key_mod) :
   SymmetricAlgorithm(key_min, key_max, key_mod),
   BLOCK_SIZE(block)
   {
   }

/*************************************************
* StreamCipher Constructor                       *
*************************************************/
StreamCipher::StreamCipher(length_type key_min, length_type key_max,
                           length_type key_mod, length_type iv_len) :
   SymmetricAlgorithm(key_min, key_max, key_mod), IV_LENGTH(iv_len)
   {
   }

/*************************************************
* BufferedComputation Constructor                *
*************************************************/
BufferedComputation::BufferedComputation(length_type olen) :
   OUTPUT_LENGTH(olen)
   {
   }

/*************************************************
* HashFunction Constructor                       *
*************************************************/
HashFunction::HashFunction(length_type hlen, length_type blen) :
   BufferedComputation(hlen), HASH_BLOCK_SIZE(blen)
   {
   }

/*************************************************
* MessageAuthenticationCode Constructor          *
*************************************************/
MessageAuthenticationCode::MessageAuthenticationCode(length_type mlen,
                                                     length_type key_min,
                                                     length_type key_max,
                                                     length_type key_mod) :
   BufferedComputation(mlen),
   SymmetricAlgorithm(key_min, key_max, key_mod)
   {
   }

/*************************************************
* Default MAC verification operation             *
*************************************************/
bool MessageAuthenticationCode::verify_mac(const byte mac[],
                                           length_type length)
   {
   SecureVector<byte> our_mac = final();
   if(our_mac.size() != length)
      return false;
   for(length_type j = 0; j != length; ++j)
      if(mac[j] != our_mac[j])
         return false;
   return true;
   }

/*************************************************
* Default StreamCipher Resync Operation          *
*************************************************/
void StreamCipher::resync(const byte[], length_type length)
   {
   if(length)
      throw Exception("The stream cipher " + name() +
                      " does not support resyncronization");
   }

/*************************************************
* Default StreamCipher Seek Operation            *
*************************************************/
void StreamCipher::seek(length_type)
   {
   throw Exception("The stream cipher " + name() + " does not support seek()");
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const byte in[], length_type n)
   {
   add_data(in, n);
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const MemoryRegion<byte>& in)
   {
   add_data(in, in.size());
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const std::string& str)
   {
   update(reinterpret_cast<const byte*>(str.data()), str.size());
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(byte in)
   {
   update(&in, 1);
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::final()
   {
   SecureVector<byte> output(OUTPUT_LENGTH);
   final_result(output);
   return output;
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const byte in[],
                                                length_type len)
   {
   update(in, len);
   return final();
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const MemoryRegion<byte>& in)
   {
   update(in, in.size());
   return final();
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const std::string& in)
   {
   update(in);
   return final();
   }

/*************************************************
* Default fast poll for EntropySources           *
*************************************************/
length_type EntropySource::fast_poll(byte buf[], length_type len)
   {
   return slow_poll(buf, len);
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
void RandomNumberGenerator::add_entropy(const byte random[],
                                        length_type length)
   {
   add_randomness(random, length);
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
length_type RandomNumberGenerator::add_entropy(EntropySource& source,
                                          bool slow_poll)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);

   length_type bytes_gathered = 0;

   if(slow_poll)
      bytes_gathered = source.slow_poll(buffer, buffer.size());
   else
      bytes_gathered = source.fast_poll(buffer, buffer.size());

   add_entropy(buffer, bytes_gathered);

   return entropy_estimate(buffer, bytes_gathered);
   }

}
