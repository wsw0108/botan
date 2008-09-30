/*************************************************
* EGD EntropySource Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_EGD_H__
#define BOTAN_ENTROPY_SRC_EGD_H__

#include <botan/rng.h>
#include <string>
#include <vector>

namespace Botan {

/*************************************************
* EGD Entropy Source                             *
*************************************************/
class EGD_EntropySource : public EntropySource
   {
   public:
      length_type slow_poll(byte[], length_type);
      EGD_EntropySource(const std::vector<std::string>& p) : paths(p) {}
   private:
      length_type do_poll(byte[], length_type, const std::string&) const;
      const std::vector<std::string> paths;
   };

}

#endif
