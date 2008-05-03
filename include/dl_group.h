/*************************************************
* Discrete Logarithm Group Header File           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_DL_PARAM_H__
#define BOTAN_DL_PARAM_H__

#include <botan/bigint.h>
#include <botan/data_src.h>

namespace Botan {

/*************************************************
* Discrete Logarithm Group                       *
*************************************************/
class BOTAN_DLL DL_Group
   {
   public:
      const BigInt& get_p() const;
      const BigInt& get_q() const;
      const BigInt& get_g() const;

      enum Format { ANSI_X9_42, ANSI_X9_57, PKCS_3 };
      enum PrimeType { Strong, Prime_Subgroup, DSA_Kosherizer };

      bool verify_group(bool) const;

      std::string PEM_encode(Format) const;
      SecureVector<byte> DER_encode(Format) const;
      void BER_decode(DataSource&, Format);
      void PEM_decode(DataSource&);

      DL_Group();
      DL_Group(const std::string&);
      DL_Group(PrimeType, length_type, length_type = 0);
      DL_Group(const MemoryRegion<byte>&, length_type = 1024, length_type = 0);
      DL_Group(const BigInt&, const BigInt&);
      DL_Group(const BigInt&, const BigInt&, const BigInt&);
   private:
      static BigInt make_dsa_generator(const BigInt&, const BigInt&);
      static SecureVector<byte> generate_dsa_primes(BigInt&, BigInt&,
                                                    length_type, length_type);
      static bool generate_dsa_primes(BigInt&, BigInt&,
                                      length_type, length_type,
                                      const MemoryRegion<byte>&);

      void init_check() const;
      void initialize(const BigInt&, const BigInt&, const BigInt&);
      bool initialized;
      BigInt p, q, g;
   };

}

#endif
