/*
* TLS Extensions
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

namespace {

Extension* new_extension(u16bit code, const MemoryRegion<byte>& val)
   {
   switch(code)
      {
      case TLSEXT_SERVER_NAME_INDICATION:
         return new Server_Name_Indicator(val);

      case TLSEXT_MAX_FRAGMENT_LENGTH:
         return new Maximum_Fragment_Length(val);

      case TLSEXT_SRP_IDENTIFIER:
         return new SRP_Identifier(val);

      case TLSEXT_USABLE_ELLIPTIC_CURVES:
         return new Supported_Elliptic_Curves(val);

      case TLSEXT_SAFE_RENEGOTIATION:
         return new Renegotation_Extension(val, true);

      case TLSEXT_SIGNATURE_ALGORITHMS:
         return new Signature_Algorithms(val);

      case TLSEXT_NEXT_PROTOCOL:
         return new Next_Protocol_Notification(val);

      case TLSEXT_HEARTBEAT_SUPPORT:
         return new Heartbeat_Support_Indicator(val);

      case TLSEXT_SESSION_TICKET:
         return new Session_Ticket(val);

      default:
         return 0; // not known
      }
   }

}

Extensions::Extensions(TLS_Data_Reader& reader)
   {
   if(reader.has_remaining())
      {
      const u16bit all_extn_size = reader.get_u16bit();

      if(reader.remaining_bytes() != all_extn_size)
         throw Decoding_Error("Bad extension size");

      while(reader.has_remaining())
         {
         const u16bit extension_code = reader.get_u16bit();
         const u16bit extension_size = reader.get_u16bit();

         MemoryVector<byte> extension_value =
            reader.get_elem<byte, MemoryVector<byte> >(extension_size);

         Extension* extn = new_extension(extension_code, extension_value);

         if(extn)
            this->add(extn);
         else // unknown/unhandled extension
            reader.discard_next(extension_size);
         }
      }
   }

MemoryVector<byte> Extensions::serialize() const
   {
   MemoryVector<byte> buf(2); // 2 bytes for length field

   for(std::map<Handshake_Extension_Type, Extension*>::const_iterator i = extensions.begin();
       i != extensions.end(); ++i)
      {
      if(i->second->empty())
         continue;

      const u16bit extn_code = i->second->type();

      MemoryVector<byte> extn_val = i->second->serialize();

      buf.push_back(get_byte(0, extn_code));
      buf.push_back(get_byte(1, extn_code));

      buf.push_back(get_byte<u16bit>(0, extn_val.size()));
      buf.push_back(get_byte<u16bit>(1, extn_val.size()));

      buf += extn_val;
      }

   const u16bit extn_size = buf.size() - 2;

   buf[0] = get_byte(0, extn_size);
   buf[1] = get_byte(1, extn_size);

   // avoid sending a completely empty extensions block
   if(buf.size() == 2)
      return MemoryVector<byte>();

   return buf;
   }

Extensions::~Extensions()
   {
   for(std::map<Handshake_Extension_Type, Extension*>::const_iterator i = extensions.begin();
       i != extensions.end(); ++i)
      {
      delete i->second;
      }

   extensions.clear();
   }

Server_Name_Indicator::Server_Name_Indicator(const MemoryRegion<byte>& buf)
   {
   // This is used by the server to confirm that it knew the name
   if(buf.empty())
      return;

   TLS_Data_Reader reader(buf);

   const size_t name_bytes = reader.get_u16bit();

   if(name_bytes + 2 != buf.size())
      throw Decoding_Error("Bad encoding of SNI extension");

   while(reader.has_remaining())
      {
      const byte name_type = reader.get_byte();

      if(name_type == 0) // DNS
         sni_host_name = reader.get_string(2, 1, 65535);
      else
         reader.discard_remaining();
      }

   reader.assert_done();
   }

MemoryVector<byte> Server_Name_Indicator::serialize() const
   {
   MemoryVector<byte> buf;

   size_t name_len = sni_host_name.size();

   buf.push_back(get_byte<u16bit>(0, name_len+3));
   buf.push_back(get_byte<u16bit>(1, name_len+3));
   buf.push_back(0); // DNS

   buf.push_back(get_byte<u16bit>(0, name_len));
   buf.push_back(get_byte<u16bit>(1, name_len));

   buf += std::make_pair(
      reinterpret_cast<const byte*>(sni_host_name.data()),
      sni_host_name.size());

   return buf;
   }

SRP_Identifier::SRP_Identifier(const MemoryRegion<byte>& buf)
   {
   TLS_Data_Reader reader(buf);

   srp_identifier = reader.get_string(1, 1, 255);

   reader.assert_done();
   }

MemoryVector<byte> SRP_Identifier::serialize() const
   {
   MemoryVector<byte> buf;

   const byte* srp_bytes =
      reinterpret_cast<const byte*>(srp_identifier.data());

   append_tls_length_value(buf, srp_bytes, srp_identifier.size(), 1);

   return buf;
   }

Renegotation_Extension::Renegotation_Extension(const MemoryRegion<byte>& val,
                                               bool decoding)
   {
   if(decoding)
      {
      TLS_Data_Reader reader(val);
      reneg_data = reader.get_range<byte>(1, 0, 255);
      reader.assert_done();
      }
   else
      reneg_data = val;
   }

MemoryVector<byte> Renegotation_Extension::serialize() const
   {
   MemoryVector<byte> buf;
   append_tls_length_value(buf, reneg_data, 1);
   return buf;
   }

size_t Maximum_Fragment_Length::fragment_size() const
   {
   switch(val)
      {
      case 1:
         return 512;
      case 2:
         return 1024;
      case 3:
         return 2048;
      case 4:
         return 4096;
      default:
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                             "Bad value in maximum fragment extension");
      }
   }

Maximum_Fragment_Length::Maximum_Fragment_Length(size_t max_fragment)
   {
   if(max_fragment == 512)
      val = 1;
   else if(max_fragment == 1024)
      val = 2;
   else if(max_fragment == 2048)
      val = 3;
   else if(max_fragment == 4096)
      val = 4;
   else
      throw std::invalid_argument("Bad setting " + to_string(max_fragment) +
                                  " for maximum fragment size");
   }

Maximum_Fragment_Length::Maximum_Fragment_Length(const MemoryRegion<byte>& buf)
   {
   if(buf.size() != 1)
      throw Decoding_Error("Bad size for maximum fragment extension");
   val = buf[0];
   }

Next_Protocol_Notification::Next_Protocol_Notification(const MemoryRegion<byte>& buf)
   {
   if(buf.empty())
      return;

   TLS_Data_Reader reader(buf);

   while(reader.has_remaining())
      {
      const std::string p = reader.get_string(1, 0, 255);
      m_protocols.push_back(p);
      }

   reader.assert_done();
   }

MemoryVector<byte> Next_Protocol_Notification::serialize() const
   {
   MemoryVector<byte> buf;

   for(size_t i = 0; i != m_protocols.size(); ++i)
      {
      const std::string p = m_protocols[i];

      if(p != "")
         append_tls_length_value(buf,
                                 reinterpret_cast<const byte*>(p.data()),
                                 p.size(),
                                 1);
      }

   return buf;
   }

std::string Supported_Elliptic_Curves::curve_id_to_name(u16bit id)
   {
   switch(id)
      {
      case 15:
         return "secp160k1";
      case 16:
         return "secp160r1";
      case 17:
         return "secp160r2";
      case 18:
         return "secp192k1";
      case 19:
         return "secp192r1";
      case 20:
         return "secp224k1";
      case 21:
         return "secp224r1";
      case 22:
         return "secp256k1";
      case 23:
         return "secp256r1";
      case 24:
         return "secp384r1";
      case 25:
         return "secp521r1";
      default:
         return ""; // something we don't know or support
      }
   }

u16bit Supported_Elliptic_Curves::name_to_curve_id(const std::string& name)
   {
   if(name == "secp160k1")
      return 15;
   if(name == "secp160r1")
      return 16;
   if(name == "secp160r2")
      return 17;
   if(name == "secp192k1")
      return 18;
   if(name == "secp192r1")
      return 19;
   if(name == "secp224k1")
      return 20;
   if(name == "secp224r1")
      return 21;
   if(name == "secp256k1")
      return 22;
   if(name == "secp256r1")
      return 23;
   if(name == "secp384r1")
      return 24;
   if(name == "secp521r1")
      return 25;

   throw Invalid_Argument("name_to_curve_id unknown name " + name);
   }

MemoryVector<byte> Supported_Elliptic_Curves::serialize() const
   {
   MemoryVector<byte> buf(2);

   for(size_t i = 0; i != m_curves.size(); ++i)
      {
      const u16bit id = name_to_curve_id(m_curves[i]);
      buf.push_back(get_byte(0, id));
      buf.push_back(get_byte(1, id));
      }

   buf[0] = get_byte<u16bit>(0, buf.size()-2);
   buf[1] = get_byte<u16bit>(1, buf.size()-2);

   return buf;
   }

Supported_Elliptic_Curves::Supported_Elliptic_Curves(const MemoryRegion<byte>& buf)
   {
   TLS_Data_Reader reader(buf);

   const size_t len = reader.get_u16bit();

   if(len + 2 != buf.size() || len % 2 == 1)
      throw Decoding_Error("Inconsistent length field in elliptic curve list");

   while(reader.has_remaining())
      {
      const u16bit id = reader.get_u16bit();
      const std::string name = curve_id_to_name(id);

      if(name != "")
         m_curves.push_back(name);
      }

   reader.assert_done();
   }

std::string Signature_Algorithms::hash_algo_name(byte code)
   {
   switch(code)
      {
      // code 1 is MD5 - ignore it

      case 2:
         return "SHA-1";
      case 3:
         return "SHA-224";
      case 4:
         return "SHA-256";
      case 5:
         return "SHA-384";
      case 6:
         return "SHA-512";
      default:
         return "";
      }
   }

byte Signature_Algorithms::hash_algo_code(const std::string& name)
   {
   if(name == "SHA-1")
      return 2;

   if(name == "SHA-224")
      return 3;

   if(name == "SHA-256")
      return 4;

   if(name == "SHA-384")
      return 5;

   if(name == "SHA-512")
      return 6;

   throw Internal_Error("Unknown hash ID " + name + " for signature_algorithms");
   }

std::string Signature_Algorithms::sig_algo_name(byte code)
   {
   switch(code)
      {
      case 1:
         return "RSA";
      case 2:
         return "DSA";
      case 3:
         return "ECDSA";
      default:
         return "";
      }
   }

byte Signature_Algorithms::sig_algo_code(const std::string& name)
   {
   if(name == "RSA")
      return 1;

   if(name == "DSA")
      return 2;

   if(name == "ECDSA")
      return 3;

   throw Internal_Error("Unknown sig ID " + name + " for signature_algorithms");
   }

MemoryVector<byte> Signature_Algorithms::serialize() const
   {
   MemoryVector<byte> buf(2);

   for(size_t i = 0; i != m_supported_algos.size(); ++i)
      {
      try
         {
         const byte hash_code = hash_algo_code(m_supported_algos[i].first);
         const byte sig_code = sig_algo_code(m_supported_algos[i].second);

         buf.push_back(hash_code);
         buf.push_back(sig_code);
         }
      catch(...)
         {}
      }

   buf[0] = get_byte<u16bit>(0, buf.size()-2);
   buf[1] = get_byte<u16bit>(1, buf.size()-2);

   return buf;
   }

Signature_Algorithms::Signature_Algorithms(const MemoryRegion<byte>& buf)
   {
   TLS_Data_Reader reader(buf);

   const size_t len = reader.get_u16bit();

   if(len + 2 != buf.size() || len % 2 == 1)
      throw Decoding_Error("Bad encoding on signature algorithms extension");

   while(reader.has_remaining())
      {
      const std::string hash_code = hash_algo_name(reader.get_byte());
      const std::string sig_code = sig_algo_name(reader.get_byte());

      // If not something we know, ignore it completely
      if(hash_code == "" || sig_code == "")
         continue;

      m_supported_algos.push_back(std::make_pair(hash_code, sig_code));
      }

   reader.assert_done();
   }

}

}
