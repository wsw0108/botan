/*************************************************
* S2K Source File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/s2k.h>
#include <botan/libstate.h>

namespace Botan {

/*************************************************
* Derive a key from a passphrase                 *
*************************************************/
OctetString S2K::derive_key(length_type key_len,
                            const std::string& passphrase) const
   {
   return derive(key_len, passphrase, salt, salt.size(), iterations());
   }

/*************************************************
* Set the number of iterations                   *
*************************************************/
void S2K::set_iterations(length_type i)
   {
   iter = i;
   }

/*************************************************
* Change the salt                                *
*************************************************/
void S2K::change_salt(const byte new_salt[], length_type length)
   {
   salt.set(new_salt, length);
   }

/*************************************************
* Change the salt                                *
*************************************************/
void S2K::change_salt(const MemoryRegion<byte>& new_salt)
   {
   change_salt(new_salt.begin(), new_salt.size());
   }

/*************************************************
* Create a new random salt                       *
*************************************************/
void S2K::new_random_salt(length_type length)
   {
   salt.create(length);
   global_state().randomize(salt, length);
   }

}
