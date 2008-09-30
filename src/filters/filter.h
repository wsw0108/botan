/*************************************************
* Filter Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_FILTER_H__
#define BOTAN_FILTER_H__

#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Filter Base Class                              *
*************************************************/
class BOTAN_DLL Filter
   {
   public:
      virtual void write(const byte[], length_type) = 0;
      virtual void start_msg() {}
      virtual void end_msg() {}
      virtual bool attachable() { return true; }
      void new_msg();
      void finish_msg();
      virtual ~Filter() {}
   protected:
      void send(const byte[], length_type);
      void send(byte input) { send(&input, 1); }
      void send(const MemoryRegion<byte>& in) { send(in.begin(), in.size()); }
      Filter();
   private:
      Filter(const Filter&) {}
      Filter& operator=(const Filter&) { return (*this); }

      friend class Pipe;
      friend class Fanout_Filter;

      length_type total_ports() const;
      length_type current_port() const { return port_num; }
      void set_port(length_type);

      length_type owns() const { return filter_owns; }

      void attach(Filter*);
      void set_next(Filter*[], length_type);
      Filter* get_next() const;

      SecureVector<byte> write_queue;
      std::vector<Filter*> next;
      length_type port_num, filter_owns;
      bool owned;
   };

/*************************************************
* Fanout Filter Base Class                       *
*************************************************/
class BOTAN_DLL Fanout_Filter : public Filter
   {
   protected:
      void incr_owns() { ++filter_owns; }

      void set_port(length_type n) { Filter::set_port(n); }
      void set_next(Filter* f[], length_type n) { Filter::set_next(f, n); }
      void attach(Filter* f) { Filter::attach(f); }
   };

}

#endif
