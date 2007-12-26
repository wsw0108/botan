/*************************************************
* PKCS #10/Self Signed Cert Creation Source File *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/x509self.h>
#include <botan/x509_ext.h>
#include <botan/x509_ca.h>
#include <botan/der_enc.h>
#include <botan/config.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <botan/pipe.h>
#include <memory>

namespace Botan {

namespace {

/*************************************************
* Shared setup for self-signed items             *
*************************************************/
MemoryVector<byte> shared_setup(const X509_Cert_Options& opts,
                                const Private_Key& key)
   {
   const Private_Key* key_pointer = &key;
   if(!dynamic_cast<const PK_Signing_Key*>(key_pointer))
      throw Invalid_Argument("Key type " + key.algo_name() + " cannot sign");

   opts.sanity_check();

   Pipe key_encoder;
   key_encoder.start_msg();
   X509::encode(key, key_encoder, RAW_BER);
   key_encoder.end_msg();

   return key_encoder.read_all();
   }

X509_DN make_dn(const X509_Cert_Options& opts)
   {
   X509_DN dn;

   dn.add_attribute("X520.CommonName", opts.common_name);
   dn.add_attribute("X520.Country", opts.country);
   dn.add_attribute("X520.State", opts.state);
   dn.add_attribute("X520.Locality", opts.locality);
   dn.add_attribute("X520.Organization", opts.organization);
   dn.add_attribute("X520.OrganizationalUnit", opts.org_unit);
   dn.add_attribute("X520.SerialNumber", opts.serial_number);

   return dn;
   }

Cert_Extension::Subject_Alternative_Name*
make_alt_name(const X509_Cert_Options& opts)
   {
   Cert_Extension::Subject_Alternative_Name* alt_name =
      new Cert_Extension::Subject_Alternative_Name();

   alt_name->add_attribute("RFC822", opts.email);
   alt_name->add_attribute("DNS", opts.dns);
   alt_name->add_attribute("URI", opts.uri);
   alt_name->add_attribute("IP", opts.ip);

   alt_name->add_othername(OIDS::lookup("PKIX.XMPPAddr"),
                           opts.xmpp, UTF8_STRING);

   return alt_name;
   }

}

namespace X509 {

/*************************************************
* Create a new self-signed X.509 certificate     *
*************************************************/
X509_Certificate create_self_signed_cert(const X509_Cert_Options& opts,
                                         const Private_Key& key)
   {
   MemoryVector<byte> pub_key = shared_setup(opts, key);

   X509_DN subject_dn = make_dn(opts);

   Key_Constraints constraints;
   if(opts.is_CA)
      constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
   else
      constraints = find_constraints(key, opts.constraints);

   Extensions extensions;

   extensions.add(new Cert_Extension::Subject_Key_ID(pub_key));
   extensions.add(new Cert_Extension::Key_Usage(constraints));
   extensions.add(
      new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));

   extensions.add(make_alt_name(opts));

   extensions.add(
      new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit));

   AlgorithmIdentifier sig_algo;

   std::auto_ptr<PK_Signer> signer(choose_sig_format(key, sig_algo));

   return X509_CA::make_cert(signer.get(), sig_algo, pub_key,
                             opts.start, opts.end,
                             subject_dn, subject_dn,
                             extensions);
   }

/*************************************************
* Create a PKCS #10 certificate request          *
*************************************************/
PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
                               const Private_Key& key)
   {
   MemoryVector<byte> pub_key = shared_setup(opts, key);

   X509_DN subject_dn = make_dn(opts);

   const u32bit PKCS10_VERSION = 0;

   Extensions extensions;

   extensions.add(
      new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit));
   extensions.add(
      new Cert_Extension::Key_Usage(
         opts.is_CA ? Key_Constraints(KEY_CERT_SIGN | CRL_SIGN) :
                      find_constraints(key, opts.constraints)
         )
      );
   extensions.add(
      new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));
   extensions.add(make_alt_name(opts));

   DER_Encoder tbs_req;

   tbs_req.start_cons(SEQUENCE)
      .encode(PKCS10_VERSION)
      .encode(subject_dn)
      .raw_bytes(pub_key)
      .start_explicit(0);

   if(opts.challenge != "")
      {
      ASN1_String challenge(opts.challenge, DIRECTORY_STRING);

      tbs_req.encode(
         Attribute("PKCS9.ChallengePassword",
                   DER_Encoder().encode(challenge).get_contents()
            )
         );
      }

   tbs_req.encode(
      Attribute("PKCS9.ExtensionRequest",
                DER_Encoder()
                   .start_cons(SEQUENCE)
                      .encode(extensions)
                   .end_cons()
               .get_contents()
         )
      )
      .end_explicit()
      .end_cons();

   AlgorithmIdentifier sig_algo;

   std::auto_ptr<PK_Signer> signer(choose_sig_format(key, sig_algo));

   DataSource_Memory source(
      X509_Object::make_signed(signer.get(), sig_algo,
                               tbs_req.get_contents())
      );

   return PKCS10_Request(source);
   }

}

}
