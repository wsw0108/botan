/*************************************************
* CBC-MAC Header File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CBC_MAC__
#define BOTAN_CBC_MAC__

#include <botan/base.h>

namespace Botan {

/*************************************************
* CBC-MAC                                        *
*************************************************/
class BOTAN_DLL CBC_MAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      MessageAuthenticationCode* clone() const;
      CBC_MAC(const std::string&);
      ~CBC_MAC();
   private:
      void add_data(const byte[], length_type);
      void final_result(byte[]);
      void key(const byte[], length_type);

      BlockCipher* e;
      SecureVector<byte> state;
      length_type position;
   };

}

#endif
