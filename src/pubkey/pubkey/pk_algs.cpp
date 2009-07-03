/*
* PK Key
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pk_algs.h>
#include <botan/oids.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

namespace Botan {

/**
* Get an PK public key object
*/
Public_Key* get_public_key(const AlgorithmIdentifier& alg_id,
                           const MemoryRegion<byte>& key_bits)
   {
   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "")
      throw Decoding_Error("Unknown algorithm OID: " +
                           alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return new RSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return new DSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return new DH_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(alg_name == "NR")
      return new NR_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_RW)
   if(alg_name == "RW")
      return new RW_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ELG")
      return new ElGamal_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return new ECDSA_PublicKey(alg_id, key_bits);
#endif

   throw Lookup_Error("PK algorithm " + alg_name + " not found");
   }

/**
* Get an PK private key object
*/
Private_Key* get_private_key(const AlgorithmIdentifier& alg_id,
                             const MemoryRegion<byte>& key_bits,
                             RandomNumberGenerator& rng)
   {
   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "")
      throw Decoding_Error("Unknown algorithm OID: " +
                           alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return new RSA_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return new DSA_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return new DH_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(alg_name == "NR")
      return new NR_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_RW)
   if(alg_name == "RW")
      return new RW_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ELG")
      return new ElGamal_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return new ECDSA_PrivateKey(alg_id, key_bits, rng);
#endif

   throw Lookup_Error("PK algorithm " + alg_name + " not found");
   }

}
