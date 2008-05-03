/*************************************************
* Serpent Source File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/serpent.h>
#include <botan/loadstor.h>

namespace Botan {

extern "C" {

void serpent_encrypt(const byte[16], byte[16], const length_type[132]);
void serpent_decrypt(const byte[16], byte[16], const length_type[132]);
void serpent_key_schedule(length_type[140]);

}

/*************************************************
* Serpent Encryption                             *
*************************************************/
void Serpent::enc(const byte in[], byte out[]) const
   {
   serpent_encrypt(in, out, round_key);
   }

/*************************************************
* Serpent Decryption                             *
*************************************************/
void Serpent::dec(const byte in[], byte out[]) const
   {
   serpent_decrypt(in, out, round_key);
   }

/*************************************************
* Serpent Key Schedule                           *
*************************************************/
void Serpent::key(const byte key[], length_type length)
   {
   SecureBuffer<length_type, 140> W;
   for(length_type j = 0; j != length / 4; ++j)
      W[j] = make_length_type(key[4*j+3], key[4*j+2], key[4*j+1], key[4*j]);
   W[length / 4] |= length_type(1) << ((length%4)*8);

   serpent_key_schedule(W);
   round_key.copy(W + 8, 132);
   }

}
