/*************************************************
* Unix Command Execution Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EXT_UNIX_CMD_H__
#define BOTAN_EXT_UNIX_CMD_H__

#include <botan/types.h>
#include <botan/data_src.h>
#include <string>
#include <vector>

namespace Botan {

/*************************************************
* Unix Program Info                              *
*************************************************/
struct Unix_Program
   {
   Unix_Program(const char* n, length_type p)
      { name_and_args = n; priority = p; working = true; }

   std::string name_and_args;
   length_type priority;
   bool working;
   };

/*************************************************
* Command Output DataSource                      *
*************************************************/
class DataSource_Command : public DataSource
   {
   public:
      length_type read(byte[], length_type);
      length_type peek(byte[], length_type, length_type) const;
      bool end_of_data() const;
      std::string id() const;

      int fd() const;

      DataSource_Command(const std::string&,
                         const std::vector<std::string>& paths);
      ~DataSource_Command();
   private:
      void create_pipe(const std::vector<std::string>&);
      void shutdown_pipe();

      const length_type MAX_BLOCK_USECS, KILL_WAIT;

      std::vector<std::string> arg_list;
      struct pipe_wrapper* pipe;
   };

}

#endif
