/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_OCSP)

#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>

using namespace Botan;

namespace {

int ocsp_check(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: ocsp subject.pem issuer.pem";
      return 2;
      }

   X509_Certificate subject(argv[1]);
   X509_Certificate issuer(argv[2]);

   Certificate_Store_In_Memory cas;
   cas.add_certificate(issuer);
   OCSP::Response resp = OCSP::online_check(issuer, subject, &cas);

   auto status = resp.status_for(issuer, subject);

   if(status == Certificate_Status_Code::VERIFIED)
      {
      std::cout << "OCSP check OK" << std::endl;
      return 0;
      }
   else
      {
      std::cout << "OCSP check failed " << Path_Validation_Result::status_string(status) << std::endl;
      return 1;
      }
   }

REGISTER_APP(ocsp_check);

}

#endif
