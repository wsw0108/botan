/*************************************************
* Zlib Compressor Header File                    *
* (C) 2001 Peter J Jones                         *
*     2001-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EXT_ZLIB_H__
#define BOTAN_EXT_ZLIB_H__

#include <botan/filter.h>

namespace Botan {

/*************************************************
* Zlib Compression Filter                        *
*************************************************/
class Zlib_Compression : public Filter
   {
   public:
      void write(const byte input[], length_type length);
      void start_msg();
      void end_msg();

      void flush();

      Zlib_Compression(length_type = 6);
      ~Zlib_Compression() { clear(); }
   private:
      void clear();
      const length_type level;
      SecureVector<byte> buffer;
      class Zlib_Stream* zlib;
   };

/*************************************************
* Zlib Decompression Filter                      *
*************************************************/
class Zlib_Decompression : public Filter
   {
   public:
      void write(const byte input[], length_type length);
      void start_msg();
      void end_msg();

      Zlib_Decompression();
      ~Zlib_Decompression() { clear(); }
   private:
      void clear();
      SecureVector<byte> buffer;
      class Zlib_Stream* zlib;
      bool no_writes;
   };

}

#endif
