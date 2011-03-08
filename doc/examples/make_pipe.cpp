#include <botan/make_pipe.h>
#include <botan/botan.h>

#include <iostream>

using namespace Botan;

int main()
   {
   LibraryInitializer init;

   Pipe* p5 = make_pipe(
     "compress:zlib(9), "
     "cipher:cbc:aes-192(aes_key, aes_iv), "
     "fork(passthrough, chain(mac:hmac-sha1(hmac_key), encode:base64))"
     );

   }
