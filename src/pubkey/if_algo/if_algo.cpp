/*************************************************
* IF Scheme Source File                          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/if_algo.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

/**
* Return the X.509 subjectPublicKeyInfo for a RSA/RW key
*/
std::pair<AlgorithmIdentifier, MemoryVector<byte> >
IF_Scheme_PublicKey::subject_public_key_info() const
   {
   DER_Encoder key_bits;

   key_bits.start_cons(SEQUENCE)
              .encode(this->get_n())
              .encode(this->get_e())
           .end_cons();

   AlgorithmIdentifier alg_id(this->get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);

   return std::make_pair(alg_id, key_bits.get_contents());
   }

std::pair<AlgorithmIdentifier, SecureVector<byte> >
IF_Scheme_PrivateKey::pkcs8_encoding() const
   {
   AlgorithmIdentifier alg_id(this->get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);

   SecureVector<byte> key_bits =
      DER_Encoder()
        .start_cons(SEQUENCE)
           .encode(static_cast<u32bit>(0))
           .encode(this->n)
           .encode(this->e)
           .encode(this->d)
           .encode(this->p)
           .encode(this->q)
           .encode(this->d1)
           .encode(this->d2)
           .encode(this->c)
        .end_cons()
        .get_contents();

   return std::make_pair(alg_id, key_bits);
   }

/**
* Check IF Scheme Public Parameters
*/
bool IF_Scheme_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(n < 35 || n.is_even() || e < 2)
      return false;
   return true;
   }

/**
* Check IF Scheme Private Parameters
*/
bool IF_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   if(n < 35 || n.is_even() || e < 2 || d < 2 || p < 3 || q < 3 || p*q != n)
      return false;

   if(!strong)
      return true;

   if(d1 != d % (p - 1) || d2 != d % (q - 1) || c != inverse_mod(q, p))
      return false;
   if(!check_prime(p, rng) || !check_prime(q, rng))
      return false;
   return true;
   }

}
