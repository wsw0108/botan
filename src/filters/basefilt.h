/*************************************************
* Basic Filters Header File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BASEFILT_H__
#define BOTAN_BASEFILT_H__

#include <botan/filter.h>

namespace Botan {

/*************************************************
* Chain                                          *
*************************************************/
class BOTAN_DLL Chain : public Fanout_Filter
   {
   public:
      void write(const byte input[], length_type length) { send(input, length); }

      Chain(Filter* = 0, Filter* = 0, Filter* = 0, Filter* = 0);
      Chain(Filter*[], length_type);
   };

/*************************************************
* Fork                                           *
*************************************************/
class BOTAN_DLL Fork : public Fanout_Filter
   {
   public:
      void write(const byte input[], length_type length) { send(input, length); }
      void set_port(length_type n) { Fanout_Filter::set_port(n); }

      Fork(Filter*, Filter*, Filter* = 0, Filter* = 0);
      Fork(Filter*[], length_type);
   };

/*************************************************
* Keyed Filter                                   *
*************************************************/
class BOTAN_DLL Keyed_Filter : public Filter
   {
   public:
      virtual void set_key(const SymmetricKey&);
      virtual void set_iv(const InitializationVector&) {}
      virtual bool valid_keylength(length_type) const;

      Keyed_Filter() { base_ptr = 0; }
   protected:
      SymmetricAlgorithm* base_ptr;
   };

}

#endif
