/*************************************************
* Parallel Source File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/par_hash.h>
#include <botan/lookup.h>

namespace Botan {

namespace {

/*************************************************
* Return the sum of the hash sizes               *
*************************************************/
length_type sum_of_hash_lengths(const std::vector<std::string>& names)
   {
   length_type sum = 0;
   for(length_type j = 0; j != names.size(); ++j)
      sum += output_length_of(names[j]);
   return sum;
   }

}

/*************************************************
* Update the hash                                *
*************************************************/
void Parallel::add_data(const byte input[], length_type length)
   {
   for(length_type j = 0; j != hashes.size(); ++j)
      hashes[j]->update(input, length);
   }

/*************************************************
* Finalize the hash                              *
*************************************************/
void Parallel::final_result(byte hash[])
   {
   length_type offset = 0;
   for(length_type j = 0; j != hashes.size(); ++j)
      {
      hashes[j]->final(hash + offset);
      offset += hashes[j]->OUTPUT_LENGTH;
      }
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string Parallel::name() const
   {
   std::string hash_names;
   for(length_type j = 0; j != hashes.size(); ++j)
      {
      if(j)
         hash_names += ',';
      hash_names += hashes[j]->name();
      }
   return "Parallel(" + hash_names + ")";
   }

/*************************************************
* Return a clone of this object                  *
*************************************************/
HashFunction* Parallel::clone() const
   {
   std::vector<std::string> names;
   for(length_type j = 0; j != hashes.size(); ++j)
      names.push_back(hashes[j]->name());
   return new Parallel(names);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void Parallel::clear() throw()
   {
   for(length_type j = 0; j != hashes.size(); ++j)
      hashes[j]->clear();
   }

/*************************************************
* Parallel Constructor                           *
*************************************************/
Parallel::Parallel(const std::vector<std::string>& names) :
   HashFunction(sum_of_hash_lengths(names))
   {
   for(length_type j = 0; j != names.size(); ++j)
      hashes.push_back(get_hash(names[j]));
   }

/*************************************************
* Parallel Destructor                            *
*************************************************/
Parallel::~Parallel()
   {
   for(length_type j = 0; j != hashes.size(); ++j)
      delete hashes[j];
   }

}
