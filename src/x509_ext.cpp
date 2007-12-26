/*************************************************
* X.509 Certificate Extensions Source File       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/x509_ext.h>
#include <botan/x509stat.h>
#include <botan/libstate.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/lookup.h>
#include <botan/parsing.h>
#include <botan/oids.h>
#include <botan/config.h>
#include <botan/bit_ops.h>
#include <botan/loadstor.h>
#include <botan/stl_util.h>
#include <botan/charset.h>
#include <algorithm>
#include <memory>

namespace Botan {

/*************************************************
* Return the OID of this extension               *
*************************************************/
OID Certificate_Extension::oid_of() const
   {
   return OIDS::lookup(oid_name());
   }

/*************************************************
* Encode an Extensions list                      *
*************************************************/
void Extensions::encode_into(DER_Encoder& to_object) const
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      {
      const Certificate_Extension* ext = extensions[j];

      std::string setting;

      if(ext->config_id() != "")
         setting = global_config().option("x509/exts/" + ext->config_id());

      if(setting == "")
         setting = "yes";

      if(setting != "yes" && setting != "no" && setting != "critical")
         throw Invalid_Argument("X509_CA:: Invalid value for option "
                                "x509/exts/" + ext->config_id() + " of " +
                                setting);

      bool is_critical = (setting == "critical");
      bool should_encode = ext->should_encode() && (setting != "no");

      if(should_encode)
         {
         to_object.start_cons(SEQUENCE)
               .encode(ext->oid_of())
               .encode_optional(is_critical, false)
               .encode(ext->encode_inner(), OCTET_STRING)
            .end_cons();
         }
      }
   }

/*************************************************
* Decode a list of Extensions                    *
*************************************************/
void Extensions::decode_from(BER_Decoder& from_source)
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   extensions.clear();

   BER_Decoder sequence = from_source.start_cons(SEQUENCE);
   while(sequence.more_items())
      {
      OID oid;
      MemoryVector<byte> contents;
      bool critical;

      sequence.start_cons(SEQUENCE)
            .decode(oid)
            .decode_optional(critical, BOOLEAN, UNIVERSAL, false)
            .decode(contents, OCTET_STRING)
            .verify_end()
         .end_cons();

      printf("saw extension oid %s (%s)\n",
             oid.as_string().c_str(),
             OIDS::lookup(oid).c_str());

      Certificate_Extension* ext =
         global_state().x509_state().get_extension(oid);

      if(!ext)
         {
         if(!critical || !should_throw)
            continue;

         throw Decoding_Error("Encountered unknown X.509 extension marked "
                              "as critical; OID = " + oid.as_string());
         }

      ext->decode_inner(contents);

      extensions.push_back(ext);
      }
   sequence.verify_end();
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Extensions::contents_to(Data_Store& subject_info,
                             Data_Store& issuer_info) const
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      extensions[j]->contents_to(subject_info, issuer_info);
   }

/*************************************************
* Copy another extensions list                   *
*************************************************/
Extensions& Extensions::copy_this(const Extensions& other)
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   extensions.clear();

   for(u32bit j = 0; j != other.extensions.size(); ++j)
      extensions.push_back(other.extensions[j]->copy());

   return (*this);
   }

/*************************************************
* Delete an Extensions list                      *
*************************************************/
Extensions::~Extensions()
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   }

namespace Cert_Extension {

/*************************************************
* Checked accessor for the path_limit member     *
*************************************************/
u32bit Basic_Constraints::get_path_limit() const
   {
   if(!is_ca)
      throw Invalid_State("Basic_Constraints::get_path_limit: Not a CA");
   return path_limit;
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Basic_Constraints::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode_if(is_ca,
                 DER_Encoder()
                    .encode(is_ca)
                    .encode_optional(path_limit, NO_CERT_PATH_LIMIT)
         )
      .end_cons()
   .get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Basic_Constraints::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_optional(is_ca, BOOLEAN, UNIVERSAL, false)
         .decode_optional(path_limit, INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT)
         .verify_end()
      .end_cons();

   if(is_ca == false)
      path_limit = 0;
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Basic_Constraints::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.BasicConstraints.is_ca", (is_ca ? 1 : 0));
   subject.add("X509v3.BasicConstraints.path_constraint", path_limit);
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Key_Usage::encode_inner() const
   {
   if(constraints == NO_CONSTRAINTS)
      throw Encoding_Error("Cannot encode zero usage constraints");

   const u32bit unused_bits = low_bit(constraints) - 1;

   SecureVector<byte> der;
   der.append(BIT_STRING);
   der.append(2 + ((unused_bits < 8) ? 1 : 0));
   der.append(unused_bits % 8);
   der.append((constraints >> 8) & 0xFF);
   if(constraints & 0xFF)
      der.append(constraints & 0xFF);

   return der;
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Key_Usage::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   BER_Object obj = ber.get_next_object();

   if(obj.type_tag != BIT_STRING || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Bad tag for usage constraint",
                        obj.type_tag, obj.class_tag);

   if(obj.value.size() != 2 && obj.value.size() != 3)
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");

   if(obj.value[0] >= 8)
      throw BER_Decoding_Error("Invalid unused bits in usage constraint");

   obj.value[obj.value.size()-1] &= (0xFF << obj.value[0]);

   u16bit usage = 0;
   for(u32bit j = 1; j != obj.value.size(); ++j)
      usage = (obj.value[j] << 8) | usage;

   constraints = Key_Constraints(usage);
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.KeyUsage", constraints);
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Subject_Key_ID::encode_inner() const
   {
   return DER_Encoder().encode(key_id, OCTET_STRING).get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Subject_Key_ID::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in).decode(key_id, OCTET_STRING).verify_end();
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Subject_Key_ID::contents_to(Data_Store& subject, Data_Store&) const
   {
   subject.add("X509v3.SubjectKeyIdentifier", key_id);
   }

/*************************************************
* Subject_Key_ID Constructor                     *
*************************************************/
Subject_Key_ID::Subject_Key_ID(const MemoryRegion<byte>& pub_key)
   {
   std::auto_ptr<HashFunction> hash(get_hash("SHA-1"));
   key_id = hash->process(pub_key);
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Authority_Key_ID::encode_inner() const
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(key_id, OCTET_STRING, ASN1_Tag(0), CONTEXT_SPECIFIC)
         .end_cons()
      .get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Authority_Key_ID::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
      .decode_optional_string(key_id, OCTET_STRING, 0);
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Authority_Key_ID::contents_to(Data_Store&, Data_Store& issuer) const
   {
   if(key_id.size())
      issuer.add("X509v3.AuthorityKeyIdentifier", key_id);
   }

namespace {

/*************************************************
* DER encode an Alternative_Name entry           *
*************************************************/
void encode_entries(DER_Encoder& encoder,
                    const std::multimap<std::string, std::string>& attr,
                    const std::string& type, ASN1_Tag tagging)
   {
   typedef std::multimap<std::string, std::string>::const_iterator iter;

   std::pair<iter, iter> range = attr.equal_range(type);
   for(iter j = range.first; j != range.second; ++j)
      {
      printf("type = %s, 1=%s 2=%s", type.c_str(), j->first.c_str(), j->second.c_str());

      if(type == "RFC822" || type == "DNS" || type == "URI")
         {
         ASN1_String asn1_string(j->second, IA5_STRING);
         encoder.add_object(tagging, CONTEXT_SPECIFIC, asn1_string.iso_8859());
         }
      else if(type == "IP")
         {
         u32bit ip = string_to_ipv4(j->second);
         byte ip_buf[4] = { 0 };
         store_be(ip, ip_buf);
         encoder.add_object(tagging, CONTEXT_SPECIFIC, ip_buf, 4);
         }
      }
   }

}

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Alternative_Name::encode_inner() const
   {
   DER_Encoder der;
   der.start_cons(SEQUENCE);

   encode_entries(der, alt_info, "RFC822", ASN1_Tag(1));
   encode_entries(der, alt_info, "DNS", ASN1_Tag(2));
   encode_entries(der, alt_info, "URI", ASN1_Tag(6));
   encode_entries(der, alt_info, "IP", ASN1_Tag(7));

   std::multimap<OID, ASN1_String>::const_iterator i;
   for(i = othernames.begin(); i != othernames.end(); ++i)
      {
      der.start_explicit(0)
         .encode(i->first)
         .start_explicit(0)
            .encode(i->second)
         .end_explicit()
      .end_explicit();
      }

   der.end_cons();

   return der.get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Alternative_Name::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder source(in);

   BER_Decoder names = source.start_cons(SEQUENCE);

   while(names.more_items())
      {
      BER_Object obj = names.get_next_object();
      if((obj.class_tag != CONTEXT_SPECIFIC) &&
         (obj.class_tag != (CONTEXT_SPECIFIC | CONSTRUCTED)))
         continue;

      ASN1_Tag tag = obj.type_tag;

      if(tag == 0)
         {
         BER_Decoder othername(obj.value);

         OID oid;
         othername.decode(oid);
         if(othername.more_items())
            {
            BER_Object othername_value_outer = othername.get_next_object();
            othername.verify_end();

            if(othername_value_outer.type_tag != ASN1_Tag(0) ||
               othername_value_outer.class_tag !=
                   (CONTEXT_SPECIFIC | CONSTRUCTED)
               )
               throw Decoding_Error("Invalid tags on otherName value");

            BER_Decoder othername_value_inner(othername_value_outer.value);

            BER_Object value = othername_value_inner.get_next_object();
            othername_value_inner.verify_end();

            ASN1_Tag value_type = value.type_tag;

            if(is_string_type(value_type) && value.class_tag == UNIVERSAL)
               add_othername(oid, ASN1::to_string(value), value_type);
            }
         }
      else if(tag == 1 || tag == 2 || tag == 6)
         {
         const std::string value = Charset::transcode(ASN1::to_string(obj),
                                                      LATIN1_CHARSET,
                                                      LOCAL_CHARSET);

         printf("decoded tag = %d, value = %s\n", tag, value.c_str());

         if(tag == 1) add_attribute("RFC822", value);
         if(tag == 2) add_attribute("DNS", value);
         if(tag == 6) add_attribute("URI", value);
         }
      else if(tag == 7)
         {
         if(obj.value.size() == 4)
            {
            u32bit ip = load_be<u32bit>(obj.value.begin(), 0);
            add_attribute("IP", ipv4_to_string(ip));
            }
         }
      }
   }

/*************************************************
* Add an attribute to an alternative name        *
*************************************************/
void Alternative_Name::add_attribute(const std::string& type,
                                     const std::string& str)
   {
   if(type == "" || str == "")
      return;

   typedef std::multimap<std::string, std::string>::iterator iter;
   std::pair<iter, iter> range = alt_info.equal_range(type);
   for(iter j = range.first; j != range.second; ++j)
      if(j->second == str)
         return;

   printf("%p adding %s, %s\n", this, type.c_str(), str.c_str());
   multimap_insert(alt_info, type, str);
   }

/*************************************************
* Add an OtherName field                         *
*************************************************/
void Alternative_Name::add_othername(const OID& oid, const std::string& value,
                                    ASN1_Tag type)
   {
   if(value != "")
      multimap_insert(othernames, oid, ASN1_String(value, type));
   }

/*************************************************
* Return all of the alternative names            *
*************************************************/
std::multimap<std::string, std::string> Alternative_Name::contents() const
   {
   std::multimap<std::string, std::string> names;

   typedef std::multimap<std::string, std::string>::const_iterator rdn_iter;
   for(rdn_iter j = alt_info.begin(); j != alt_info.end(); ++j)
      multimap_insert(names, j->first, j->second);

   typedef std::multimap<OID, ASN1_String>::const_iterator on_iter;
   for(on_iter j = othernames.begin(); j != othernames.end(); ++j)
      multimap_insert(names, OIDS::lookup(j->first), j->second.value());

   return names;
   }

/*************************************************
* Subject_Alternative_Name Constructor           *
*************************************************/
Subject_Alternative_Name::Subject_Alternative_Name(const std::string& email,
                                                   const std::string& uri,
                                                   const std::string& dns,
                                                   const std::string& ip)
   {
   add_attribute("RFC822", email);
   add_attribute("DNS", dns);
   add_attribute("URI", uri);
   add_attribute("IP", ip);
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Subject_Alternative_Name::contents_to(Data_Store& subject_info,
                                           Data_Store&) const
   {
   printf("%p adding subject info contents to %p\n", this, &subject_info);

   std::multimap<std::string, std::string> names = contents();
   std::multimap<std::string, std::string>::iterator i = names.begin();
   while(i != names.end())
      {
      printf("i->first = %s i->second = %s\n",
             i->first.c_str(),
             i->second.c_str());
      ++i;
      }
   printf("done\n");

   subject_info.add(contents());
   }

/*************************************************
* Issuer_Alternative_Name Constructor            *
*************************************************/
Issuer_Alternative_Name::Issuer_Alternative_Name(const std::string& email,
                                                 const std::string& uri,
                                                 const std::string& dns,
                                                 const std::string& ip)
   {
   add_attribute("RFC822", email);
   add_attribute("DNS", dns);
   add_attribute("URI", uri);
   add_attribute("IP", ip);
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Issuer_Alternative_Name::contents_to(Data_Store&, Data_Store& issuer_info) const
   {
   issuer_info.add(contents());
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Extended_Key_Usage::encode_inner() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(oids)
      .end_cons()
   .get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Extended_Key_Usage::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_list(oids)
      .end_cons();
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Extended_Key_Usage::contents_to(Data_Store& subject, Data_Store&) const
   {
   for(u32bit j = 0; j != oids.size(); ++j)
      subject.add("X509v3.ExtendedKeyUsage", oids[j].as_string());
   }

namespace {

/*************************************************
* A policy specifier                             *
*************************************************/
class Policy_Information : public ASN1_Object
   {
   public:
      OID oid;

      void encode_into(DER_Encoder& codec) const
         {
         codec.start_cons(SEQUENCE)
            .encode(oid)
            .end_cons();
         }

      void decode_from(BER_Decoder& codec)
         {
         codec.start_cons(SEQUENCE)
            .decode(oid)
            .discard_remaining()
            .end_cons();
         }
   };

}

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Certificate_Policies::encode_inner() const
   {
   throw Exception("Certificate_Policies::encode_inner: Bugged");

   std::vector<Policy_Information> policies;

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode_list(policies)
      .end_cons()
   .get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Certificate_Policies::decode_inner(const MemoryRegion<byte>& in)
   {
   std::vector<Policy_Information> policies;

   BER_Decoder(in)
      .start_cons(SEQUENCE)
         .decode_list(policies)
      .end_cons();
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void Certificate_Policies::contents_to(Data_Store& info, Data_Store&) const
   {
   for(u32bit j = 0; j != oids.size(); ++j)
      info.add("X509v3.ExtendedKeyUsage", oids[j].as_string());
   }

/*************************************************
* Checked accessor for the crl_number member     *
*************************************************/
u32bit CRL_Number::get_crl_number() const
   {
   if(!has_value)
      throw Invalid_State("CRL_Number::get_crl_number: Not set");
   return crl_number;
   }

/*************************************************
* Copy a CRL_Number extension                    *
*************************************************/
CRL_Number* CRL_Number::copy() const
   {
   if(!has_value)
      throw Invalid_State("CRL_Number::copy: Not set");
   return new CRL_Number(crl_number);
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> CRL_Number::encode_inner() const
   {
   return DER_Encoder().encode(crl_number).get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void CRL_Number::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in).decode(crl_number);
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void CRL_Number::contents_to(Data_Store& subject_info, Data_Store&) const
   {
   subject_info.add("X509v3.CRLNumber", crl_number);
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> CRL_ReasonCode::encode_inner() const
   {
   return DER_Encoder()
      .encode(static_cast<u32bit>(reason), ENUMERATED, UNIVERSAL)
   .get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void CRL_ReasonCode::decode_inner(const MemoryRegion<byte>& in)
   {
   u32bit reason_code = 0;
   BER_Decoder(in).decode(reason_code, ENUMERATED, UNIVERSAL);
   reason = static_cast<CRL_Code>(reason_code);
   }

/*************************************************
* Write the extensions to an info store          *
*************************************************/
void CRL_ReasonCode::contents_to(Data_Store& subject_info, Data_Store&) const
   {
   subject_info.add("X509v3.CRLReasonCode", reason);
   }

}

}
