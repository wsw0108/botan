/*************************************************
* DataSource Source File                         *
* (C) 1999-2007 Jack Lloyd                       *
*     2005 Matthew Gregan                        *
*************************************************/

#include <botan/data_src.h>
#include <fstream>
#include <algorithm>

namespace Botan {

/*************************************************
* Read a single byte from the DataSource         *
*************************************************/
length_type DataSource::read_byte(byte& out)
   {
   return read(&out, 1);
   }

/*************************************************
* Peek a single byte from the DataSource         *
*************************************************/
length_type DataSource::peek_byte(byte& out) const
   {
   return peek(&out, 1, 0);
   }

/*************************************************
* Discard the next N bytes of the data           *
*************************************************/
length_type DataSource::discard_next(length_type n)
   {
   length_type discarded = 0;
   byte dummy;
   for(length_type j = 0; j != n; ++j)
      discarded = read_byte(dummy);
   return discarded;
   }

/*************************************************
* Read from a memory buffer                      *
*************************************************/
length_type DataSource_Memory::read(byte out[], length_type length)
   {
   length_type got = std::min<length_type>(source.size() - offset, length);
   copy_mem(out, source + offset, got);
   offset += got;
   return got;
   }

/*************************************************
* Peek into a memory buffer                      *
*************************************************/
length_type DataSource_Memory::peek(byte out[], length_type length,
                               length_type peek_offset) const
   {
   const length_type bytes_left = source.size() - offset;
   if(peek_offset >= bytes_left) return 0;

   length_type got = std::min(bytes_left - peek_offset, length);
   copy_mem(out, source + offset + peek_offset, got);
   return got;
   }

/*************************************************
* Check if the memory buffer is empty            *
*************************************************/
bool DataSource_Memory::end_of_data() const
   {
   return (offset == source.size());
   }

/*************************************************
* DataSource_Memory Constructor                  *
*************************************************/
DataSource_Memory::DataSource_Memory(const byte in[], length_type length)
   {
   source.set(in, length);
   offset = 0;
   }

/*************************************************
* DataSource_Memory Constructor                  *
*************************************************/
DataSource_Memory::DataSource_Memory(const MemoryRegion<byte>& in)
   {
   source = in;
   offset = 0;
   }

/*************************************************
* DataSource_Memory Constructor                  *
*************************************************/
DataSource_Memory::DataSource_Memory(const std::string& in)
   {
   source.set(reinterpret_cast<const byte*>(in.data()), in.length());
   offset = 0;
   }

/*************************************************
* Read from a stream                             *
*************************************************/
length_type DataSource_Stream::read(byte out[], length_type length)
   {
   source->read(reinterpret_cast<char*>(out), length);
   if(source->bad())
      throw Stream_IO_Error("DataSource_Stream::read: Source failure");

   length_type got = source->gcount();
   total_read += got;
   return got;
   }

/*************************************************
* Peek into a stream                             *
*************************************************/
length_type DataSource_Stream::peek(byte out[], length_type length,
                                    length_type offset) const
   {
   if(end_of_data())
      throw Invalid_State("DataSource_Stream: Cannot peek when out of data");

   length_type got = 0;

   if(offset)
      {
      SecureVector<byte> buf(offset);
      source->read(reinterpret_cast<char*>(buf.begin()), buf.size());
      if(source->bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = source->gcount();
      }

   if(got == offset)
      {
      source->read(reinterpret_cast<char*>(out), length);
      if(source->bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = source->gcount();
      }

   if(source->eof())
      source->clear();
   source->seekg(total_read, std::ios::beg);

   return got;
   }

/*************************************************
* Check if the stream is empty or in error       *
*************************************************/
bool DataSource_Stream::end_of_data() const
   {
   return (!source->good());
   }

/*************************************************
* Return a human-readable ID for this stream     *
*************************************************/
std::string DataSource_Stream::id() const
   {
   return identifier;
   }

/*************************************************
* DataSource_Stream Constructor                  *
*************************************************/
DataSource_Stream::DataSource_Stream(const std::string& path,
                                     bool use_binary) :
   identifier(path), owner(true)
   {
   if(use_binary)
      source = new std::ifstream(path.c_str(), std::ios::binary);
   else
      source = new std::ifstream(path.c_str());

   if(!source->good())
      throw Stream_IO_Error("DataSource: Failure opening file " + path);

   total_read = 0;
   }

/*************************************************
* DataSource_Stream Constructor                  *
*************************************************/
DataSource_Stream::DataSource_Stream(std::istream& in,
                                     const std::string& name) :
   identifier(name), owner(false)
   {
   source = &in;
   total_read = 0;
   }

/*************************************************
* DataSource_Stream Destructor                   *
*************************************************/
DataSource_Stream::~DataSource_Stream()
   {
   if(owner)
      delete source;
   }

}
