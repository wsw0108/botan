/*************************************************
* Device EntropySource Header File               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_DEVICE_H__
#define BOTAN_ENTROPY_SRC_DEVICE_H__

#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Device Based Entropy Source                    *
*************************************************/
class Device_EntropySource : public EntropySource
   {
   public:
      Device_EntropySource(const std::vector<std::string>& fs) : fsnames(fs) {}
      length_type slow_poll(byte[], length_type);
   private:
      std::vector<std::string> fsnames;
   };

}

#endif
