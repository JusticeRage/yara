/*
    This file is part of Spike Guard.

    Spike Guard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Spike Guard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _YARA_WRAPPER_H_
#define _YARA_WRAPPER_H_

#include <iostream>
#include <string>
#include <sstream>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <exception>
#include <algorithm>

#include <stdlib.h>

#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/system/api_config.hpp>

extern "C" {

#include <yara/yara.h>

};

#include "color.h"

#if defined BOOST_WINDOWS_API
	#ifdef YARA_EXPORT
		#define Y_DECLSPEC __declspec(dllexport)
	#else
		#define Y_DECLSPEC __declspec(dllimport)
	#endif
#else
	#define Y_DECLSPEC
#endif

namespace yara {

/**
 *	@brief	A callback used when yara iterates through its signatures.
 *
 *	Using Yara metadata allows me to return more expressive results than simple, alphanumeric rule names.
 *
 *	@param	void* data	A pointer to a pmatch object which will be filled with the matching rules' metadata.
 */
int get_match_data(int message, YR_RULE* rule, void* data);

/**
 *	@brief	An object representing Yara results.
 *
 *	It contains the metadata of the matching rule, and the pattern that was found
 *	in the input.
 */
class Match
{
public:
	Match() : _metadata(), _found_strings() {}
	typedef std::map<std::string, std::string> match_metadata;

	void add_metadata(const std::string& key, const std::string& value)	{
		_metadata[key] = value;
	}

	void add_found_string(const std::string found) {
		_found_strings.insert(found);
	}

	match_metadata get_metadata() const { return _metadata; }
	std::set<std::string> get_found_strings() const { return _found_strings; }

	/**
	 *	@brief	The [] operator provides fast access to the match's metadata.
	 *
	 *	@param	const std::string& key The metadata's identifier.
	 *
	 *	@param	The corresponding metadata.
	 */
	std::string operator[](const std::string& key) { return _metadata[key]; }

private:
	match_metadata			_metadata;
	std::set<std::string>	_found_strings;
};

typedef boost::shared_ptr<Match> pMatch;
typedef std::vector<pMatch> match_vector;
typedef boost::shared_ptr<match_vector > matches;
typedef boost::shared_ptr<const match_vector > const_matches;

class Yara
{
public:
	Y_DECLSPEC Yara();
	Y_DECLSPEC virtual ~Yara();
	Y_DECLSPEC static boost::shared_ptr<Yara> create();

	/**
	 *	@brief	Loads rules inside a Yara engine.
	 *
	 *	Scanning will not work before rules have been loaded.
	 *
	 *	@param	const std::string& rule_filename The file containing the rules.
	 *
	 *	@return	Whether the rules were loaded successfully.
	 */
	Y_DECLSPEC bool load_rules(const std::string& rule_filename);

	/**
	 *	@brief	Tries to match a given input with the currently loaded Yara rules.
	 *
	 *	@param	const std::vector<boost::uint8_t>& bytes The bytes to scan.
	 *
	 *	@return	A map containing the rule's metadata for all matching signatures.
	 */
	Y_DECLSPEC const_matches scan_bytes(const std::vector<boost::uint8_t>& bytes);

	/**
	 *	@brief	Tries to match an input file with the currently loaded Yara rules.
	 *
	 *	@param	const std::string& path The path to the file to scan..
	 *
	 *	@return	A map containing the rule's metadata for all matching signatures.
	 */
	Y_DECLSPEC const_matches scan_file(const std::string& path);

	void operator delete(void*);

private:
	// Do not allow users to allocate objects on the heap themselves. If this happens across DLL
	// boundaries, the heap will get corrupted!
	void* operator new(size_t);
	void* operator new[](size_t);

	void _clean_compiler_and_rules();

	YR_COMPILER*	_compiler;
	YR_RULES*		_rules;

	std::string		_current_rules;

	static int		_instance_count;
};

typedef boost::shared_ptr<Yara> pYara;

} // !namespace yara

#endif // !_YARA_WRAPPER_H_
