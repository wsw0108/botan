/*
* Exceptions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/exceptn.h>

namespace Botan {

/*
* Constructor for Algorithm_Not_Found
*/
Algorithm_Not_Found::Algorithm_Not_Found(const std::string& name)
   {
   set_msg("Could not find any algorithm named \"" + name + "\"");
   }

/*
* Constructor for Invalid_Algorithm_Name
*/
Invalid_Algorithm_Name::Invalid_Algorithm_Name(const std::string& name)
   {
   set_msg("Invalid algorithm name: " + name);
   }

/*
* Constructor for Config_Error
*/
Config_Error::Config_Error(const std::string& err, u32bit line)
   {
   set_msg("Config error at line " + to_string(line) + ": " + err);
   }

}
