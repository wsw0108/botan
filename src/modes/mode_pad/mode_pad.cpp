/*************************************************
* CBC Padding Methods Source File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/mode_pad.h>
#include <botan/util.h>

namespace Botan {

/*************************************************
* Default amount of padding                      *
*************************************************/
length_type BlockCipherModePaddingMethod::pad_bytes(length_type bs,
                                                    length_type pos) const
   {
   return (bs - pos);
   }

/*************************************************
* Pad with PKCS #7 Method                        *
*************************************************/
void PKCS7_Padding::pad(byte block[], length_type size,
                        length_type position) const
   {
   for(length_type j = 0; j != size; ++j)
      block[j] = (size-position);
   }

/*************************************************
* Unpad with PKCS #7 Method                      *
*************************************************/
length_type PKCS7_Padding::unpad(const byte block[], length_type size) const
   {
   length_type position = block[size-1];
   if(position > size)
      throw Decoding_Error(name());
   for(length_type j = size-position; j != size-1; ++j)
      if(block[j] != position)
         throw Decoding_Error(name());
   return (size-position);
   }

/*************************************************
* Query if the size is valid for this method     *
*************************************************/
bool PKCS7_Padding::valid_blocksize(length_type size) const
   {
   if(size > 0 && size < 256)
      return true;
   else
      return false;
   }

/*************************************************
* Pad with ANSI X9.23 Method                     *
*************************************************/
void ANSI_X923_Padding::pad(byte block[], length_type size,
                            length_type position) const
   {
   for(length_type j = 0; j != size-position; ++j)
      block[j] = 0;
   block[size-position-1] = (size-position);
   }

/*************************************************
* Unpad with ANSI X9.23 Method                   *
*************************************************/
length_type ANSI_X923_Padding::unpad(const byte block[],
                                     length_type size) const
   {
   length_type position = block[size-1];
   if(position > size)
      throw Decoding_Error(name());
   for(length_type j = size-position; j != size-1; ++j)
      if(block[j] != 0)
         throw Decoding_Error(name());
   return (size-position);
   }

/*************************************************
* Query if the size is valid for this method     *
*************************************************/
bool ANSI_X923_Padding::valid_blocksize(length_type size) const
   {
   if(size > 0 && size < 256)
      return true;
   else
      return false;
   }

/*************************************************
* Pad with One and Zeros Method                  *
*************************************************/
void OneAndZeros_Padding::pad(byte block[], length_type size,
                              length_type) const
   {
   block[0] = 0x80;
   for(length_type j = 1; j != size; ++j)
      block[j] = 0x00;
   }

/*************************************************
* Unpad with One and Zeros Method                *
*************************************************/
length_type OneAndZeros_Padding::unpad(const byte block[],
                                       length_type size) const
   {
   while(size)
      {
      if(block[size-1] == 0x80)
         break;
      if(block[size-1] != 0x00)
         throw Decoding_Error(name());
      size--;
      }
   if(!size)
      throw Decoding_Error(name());
   return (size-1);
   }

/*************************************************
* Query if the size is valid for this method     *
*************************************************/
bool OneAndZeros_Padding::valid_blocksize(length_type size) const
   {
   if(size) return true;
   else     return false;
   }

}
