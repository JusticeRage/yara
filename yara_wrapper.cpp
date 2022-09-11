/*
	This file is part of Manalyze.

	Manalyze is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Manalyze is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "yara_wrapper.h"

namespace yara
{

namespace bfs = boost::filesystem;

Yara::Yara()
{
	_compiler = nullptr;
	_rules = nullptr;
	_current_rules = "";
}

// ----------------------------------------------------------------------------

Yara::~Yara()
{
	_clean_compiler_and_rules();
}

// ----------------------------------------------------------------------------

pYara Yara::create() {
	return boost::make_shared<Yara>();
}

// ----------------------------------------------------------------------------

void Yara::initialize() {
    yr_initialize();
}

// ----------------------------------------------------------------------------

void Yara::finalize() {
    yr_finalize();
}

// ----------------------------------------------------------------------------
void* Yara::operator new(size_t size)
{
	void* p = malloc(size);
	if (p == nullptr)
		throw std::bad_alloc();
	return p;
}

// ----------------------------------------------------------------------------

void Yara::operator delete(void* p)
{
	if (p != nullptr) {
		free(p);
	}
}

// ----------------------------------------------------------------------------

void Yara::_clean_compiler_and_rules()
{
	if (_compiler != nullptr)
	{
		yr_compiler_destroy(_compiler);
		_compiler = nullptr;
	}
	if (_rules != nullptr)
	{
		yr_rules_destroy(_rules);
		_rules = nullptr;
	}
}

// ----------------------------------------------------------------------------

bool Yara::load_rules(const std::string& rule_filename)
{
	if (_current_rules == rule_filename) {
		return true;
	}
	else { // The previous rules and compiler have to be freed manually.
		_clean_compiler_and_rules();
	}

	bool res = false;
	int retval;

	if (!bfs::exists(rule_filename)) {
		return false;
	}

	// Look for a compiled version of the rule file first.
	if (bfs::exists(rule_filename + "c")) // File extension is .yarac instead of .yara.
	{
		// If the compiled rules are older than their source, recompile them.
		if (bfs::exists(rule_filename) && bfs::last_write_time(rule_filename) > bfs::last_write_time(rule_filename + "c"))
		{
			PRINT_WARNING << "New version of " << rule_filename << " detected. The rules will be recompiled." << std::endl;
			boost::filesystem::remove(rule_filename + "c");
			retval = ERROR_INVALID_FILE;
		}
		else {
			retval = yr_rules_load((rule_filename + "c").c_str(), &_rules);
		}
	}
	else {
		retval = yr_rules_load(rule_filename.c_str(), &_rules);
	}

	// Yara rules compiled with a previous Yara version. Delete and recompile.
	if (retval == ERROR_UNSUPPORTED_FILE_VERSION && bfs::exists(rule_filename + "c")) {
		boost::filesystem::remove(rule_filename + "c");
	}

	if (retval != ERROR_SUCCESS && retval != ERROR_INVALID_FILE && retval != ERROR_UNSUPPORTED_FILE_VERSION)
	{
		PRINT_ERROR << "Could not load yara rules (" << translate_error(retval) << ")." << std::endl;
		return false;
	}

	if (retval == ERROR_SUCCESS) 
	{
		_current_rules = rule_filename;
		return true;
	}
	else if (retval == ERROR_INVALID_FILE) // Uncompiled rules
	{
		if (yr_compiler_create(&_compiler) != ERROR_SUCCESS) {
			return false;
		}
		yr_compiler_set_callback(_compiler, compiler_callback, nullptr);
		FILE* rule_file = fopen(rule_filename.c_str(), "r");
		if (rule_file == nullptr) {
			return false;
		}
		retval = yr_compiler_add_file(_compiler, rule_file, nullptr, rule_filename.c_str());
		if (retval != 0)
		{
			PRINT_ERROR << "Could not compile yara rules (" << retval << " error(s))." << std::endl;
			goto END;
		}
		retval = yr_compiler_get_rules(_compiler, &_rules);
		if (retval != ERROR_SUCCESS) {
			goto END;
		}

		// Save the compiled rules to improve load times.
		retval = yr_rules_save(_rules, (rule_filename + "c").c_str());
		if (retval != ERROR_SUCCESS) {
			goto END;
		}

		res = true;
		_current_rules = rule_filename;
		END:
		fclose(rule_file);
	}
	return res;
}

// ----------------------------------------------------------------------------

const_matches Yara::scan_bytes(const std::vector<boost::uint8_t>& bytes) const
{
	pcallback_data cb_data(new callback_data);
	cb_data->yara_matches = boost::make_shared<match_vector>();
	int retval;
	if (_rules == nullptr || bytes.empty())
	{
		if (_rules == nullptr) {
			PRINT_ERROR << "No Yara rules loaded!" << std::endl;
		}
		return cb_data->yara_matches;
	}

	// Make a copy of the input buffer, because we can't be sure that Yara will not modify it
	// and the constness of the input has to be guaranteed.
	std::vector<boost::uint8_t> copy(bytes.begin(), bytes.end());

	// Yara setup done. Scan the file.
	retval = yr_rules_scan_mem(_rules,
							   &copy[0],		// The bytes to scan
							   bytes.size(),	// Number of bytes
							   SCAN_FLAGS_PROCESS_MEMORY,
							   get_match_data,
							   &cb_data,			// The vector to fill
							   0);				// No timeout)

	if (retval != ERROR_SUCCESS)
	{
		#ifdef _DEBUG
			PRINT_ERROR << "Yara error: " << translate_error(retval) << " ("  << _current_rules << ")" << std::endl;
		#else
			PRINT_ERROR << "Yara error: " << translate_error(retval) << std::endl;
		#endif
		cb_data->yara_matches->clear();
	}

	return cb_data->yara_matches;
}

// ----------------------------------------------------------------------------

const_matches Yara::scan_file(const std::string& path, pmanape_data pe_data) const
{
	pcallback_data cb_data(new callback_data);
	cb_data->yara_matches = boost::make_shared<match_vector>();
	cb_data->pe_info = std::move(pe_data);
	int retval;
	if (_rules == nullptr)
	{
		PRINT_ERROR << "No Yara rules loaded!" << std::endl;
		return cb_data->yara_matches;
	}

	retval = yr_rules_scan_file(_rules,
								path.c_str(),
								SCAN_FLAGS_PROCESS_MEMORY,
								get_match_data,
								&cb_data,
								0);

	if (retval != ERROR_SUCCESS)
	{
		#ifdef _DEBUG
			PRINT_ERROR << "Yara error: " << translate_error(retval) << " ("  << _current_rules << ")" << std::endl;
		#else
			PRINT_ERROR << "Yara error: " << translate_error(retval) << std::endl;
		#endif
		cb_data->yara_matches->clear();
	}
	return cb_data->yara_matches;
}

// ----------------------------------------------------------------------------

void compiler_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data)
{
	if (error_level == YARA_ERROR_LEVEL_ERROR)
	{
		PRINT_ERROR << "[Yara compiler] " << (file_name != nullptr ? file_name : "") << " (" << line_number
			<< ") : " << message << std::endl;
	}
	#ifdef _DEBUG // Warnings are very verbose, do not display them unless this is a debug release.
		if (error_level == YARA_ERROR_LEVEL_WARNING)
		{
			PRINT_WARNING << "[Yara compiler] " << (file_name != nullptr ? file_name : "") << "("
				<< line_number << ") : " << message << std::endl;
		}
	#endif // _DEBUG
}

// ----------------------------------------------------------------------------

int get_match_data(YR_SCAN_CONTEXT* ctx, int message, void* message_data, void* data)
{
	matches target;
	YR_META* meta;
	YR_STRING* s;
	YR_RULE* rule;
	pMatch m;
	YR_MODULE_IMPORT* mi; // Used for the CALLBACK_MSG_IMPORT_MODULE message.
	auto cb_data = (pcallback_data*) data;
	if (!cb_data)
	{
		PRINT_ERROR << "Yara wrapper callback called with no data!" << std::endl;
		return ERROR_CALLBACK_ERROR;
	}

	switch (message)
	{
		case CALLBACK_MSG_RULE_MATCHING:
			rule = (YR_RULE*) message_data;
			target = cb_data->get()->yara_matches;
			m = boost::make_shared<Match>();

            yr_rule_metas_foreach(rule, meta)
			{
				m->add_metadata(std::string(meta->identifier), meta->string);
				++meta;
			}
            yr_rule_strings_foreach(rule, s)
			{
                YR_MATCH* match;
                yr_string_matches_foreach(ctx, s, match)
				{
                    if (!STRING_IS_HEX(s))
                    {
                        std::string found((char*) match->data, match->data_length);
                        // Yara inserts null bytes when it matches unicode strings. Dirty fix to remove them all.
                        found.erase(std::remove(found.begin(), found.end(), '\0'), found.end());
                        m->add_found_string(found, match->offset);
                    }
                    else
                    {
                        std::stringstream ss;
                        ss << std::hex;
                        for (int i = 0; i < std::min(20, match->data_length); i++) {
                            ss << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(match->data[i]) << " "; // Don't interpret as a char
                        }
                        if (match->data_length > 20) {
                            ss << "...";
                        }
                        m->add_found_string(ss.str(), match->offset);
                    }
				}
				++s;
			}

			target->push_back(m);
			return CALLBACK_CONTINUE; // Don't stop on the first matching rule.

		case CALLBACK_MSG_RULE_NOT_MATCHING:
		case CALLBACK_MSG_MODULE_IMPORTED:
			return CALLBACK_CONTINUE;

		// Detect when the ManaPE module is loaded
		case CALLBACK_MSG_IMPORT_MODULE:
			mi = (YR_MODULE_IMPORT*) message_data;
			if (std::string(mi->module_name) == "manape")
			{
				if (cb_data->get()->pe_info == nullptr)
				{
					PRINT_ERROR << "Yara rule imports the ManaPE module, but no ManaPE data was given!" << std::endl;
					return ERROR_CALLBACK_ERROR;
				}
				mi->module_data = &*(cb_data->get()->pe_info);
			}
			return ERROR_SUCCESS;

		case CALLBACK_MSG_SCAN_FINISHED:
			return ERROR_SUCCESS;

		default:
			PRINT_WARNING << "Yara callback received an unhandled message (" << message << ")." << std::endl;
			return ERROR_SUCCESS;
	}
}

} // !namespace yara
