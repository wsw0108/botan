/*
* Create a Pipe
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/make_pipe.h>
#include <botan/hex_filt.h>
#include <memory>
#include <string>
#include <queue>

#include <iostream>

namespace Botan {

namespace {

Filter* make_filter(const std::string& filter_name)
   {
   if(filter_name == "encode:hex")
      return new Hex_Encoder;
   else if(filter_name == "decode:hex")
      return new Hex_Decoder;
   else
      throw Invalid_Argument("Unknown filter name '" + filter_name + "'");
   }

class pipe_language_lexer
   {
   public:
      pipe_language_lexer(const std::string& spec)
         {
         std::string current;

         for(size_t i = 0; i != spec.size(); ++i)
            {
            const char c = spec[i];

            if(c == ' ')
               continue;

            if(c == '|' || c == ',' || c == '(' || c == ')')
               {
               if(!current.empty())
                  {
                  tokens.push(current);
                  current.clear();
                  }
               tokens.push(std::string(1, c));
               continue;
               }

            current.push_back(c);
            }

         if(!current.empty())
            tokens.push(current);

         }

      std::string next_token()
         {
         std::string result = "";

         if(!tokens.empty())
            {
            result = tokens.front();
            tokens.pop();
            }

         return result;
         }

   private:
      std::queue<std::string> tokens;
   };

}

Pipe* make_pipe(const std::string& filter_spec)
   {
   std::auto_ptr<Pipe> result(new Pipe);

   pipe_language_lexer lex(filter_spec);

   std::string token = lex.next_token();
   while(!token.empty())
      {
      std::cout << token << "\n";
      token = lex.next_token();
      }

   return result.release();
   }

}
