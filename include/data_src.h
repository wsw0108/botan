/*************************************************
* DataSource Header File                         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_DATA_SRC_H__
#define BOTAN_DATA_SRC_H__

#include <botan/base.h>
#include <iosfwd>

namespace Botan {

/*************************************************
* Generic DataSource Interface                   *
*************************************************/
class BOTAN_DLL DataSource
   {
   public:
      virtual length_type read(byte[], length_type) = 0;
      virtual length_type peek(byte[], length_type, length_type) const = 0;
      virtual bool end_of_data() const = 0;
      virtual std::string id() const { return ""; }

      length_type read_byte(byte&);
      length_type peek_byte(byte&) const;
      length_type discard_next(length_type);

      DataSource() {}
      virtual ~DataSource() {}
   private:
      DataSource& operator=(const DataSource&) { return (*this); }
      DataSource(const DataSource&);
   };

/*************************************************
* Memory-Based DataSource                        *
*************************************************/
class BOTAN_DLL DataSource_Memory : public DataSource
   {
   public:
      length_type read(byte[], length_type);
      length_type peek(byte[], length_type, length_type) const;
      bool end_of_data() const;

      DataSource_Memory(const std::string&);
      DataSource_Memory(const byte[], length_type);
      DataSource_Memory(const MemoryRegion<byte>&);
   private:
      SecureVector<byte> source;
      length_type offset;
   };

/*************************************************
* Stream-Based DataSource                        *
*************************************************/
class BOTAN_DLL DataSource_Stream : public DataSource
   {
   public:
      length_type read(byte[], length_type);
      length_type peek(byte[], length_type, length_type) const;
      bool end_of_data() const;
      std::string id() const;

      DataSource_Stream(std::istream&, const std::string& id = "");
      DataSource_Stream(const std::string&, bool = false);
      ~DataSource_Stream();
   private:
      const std::string identifier;
      const bool owner;

      std::istream* source;
      length_type total_read;
   };

}

#endif
