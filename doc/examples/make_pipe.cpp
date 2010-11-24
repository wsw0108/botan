#include <botan/make_pipe.h>
#include <botan/botan.h>

#include <iostream>

using namespace Botan;

int main()
   {
   LibraryInitializer init;

   Pipe* p1 = make_pipe("");

   std::cout << p1 << "\n";
   delete p1;

   Pipe* p2 = make_pipe("encode:hex");
   std::cout << p2 << "\n";
   delete p2;

   /*
   Pipe* p3 = make_pipe("decode:hex");

   Pipe p4 = make_pipe("encode:hex | decode:hex");

   Pipe* p5 = make_pipe("compress:zlib(9) |"
                        "cipher:cbc:aes-192(aes_key, aes_iv) |"
                        "(passthrough,"
                        "(hmac-sha1(hmac_key) | encode:base64))");
   */

   }
