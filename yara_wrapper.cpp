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

#include <boost/system/api_config.hpp>
#include <boost/system/error_code.hpp>

#include <cstdlib>

namespace yara
{

namespace bfs = boost::filesystem;

namespace {

bool is_up_to_date(const bfs::path& compiled, const bfs::path& source)
{
	if (!bfs::exists(compiled) || !bfs::exists(source)) {
		return false;
	}

	return bfs::last_write_time(compiled) >= bfs::last_write_time(source);
}

std::string get_env_string(const char* name)
{
	const char* value = std::getenv(name);
	return value ? std::string(value) : std::string();
}

std::string select_cache_root()
{
	const std::string env_dir = get_env_string("MANALYZE_CACHE_DIR");
	if (!env_dir.empty()) {
		return env_dir;
	}

#ifdef BOOST_WINDOWS_API
	const std::string local_app_data = get_env_string("LOCALAPPDATA");
	if (!local_app_data.empty()) {
		return (bfs::path(local_app_data) / "Manalyze").string();
	}
#else
	const std::string xdg_cache = get_env_string("XDG_CACHE_HOME");
	if (!xdg_cache.empty()) {
		return (bfs::path(xdg_cache) / "manalyze").string();
	}

	const std::string home = get_env_string("HOME");
	if (!home.empty()) {
		return (bfs::path(home) / ".cache" / "manalyze").string();
	}
#endif

	return ".";
}

bfs::path compiled_rules_path(const std::string& rule_filename)
{
	const bfs::path source(rule_filename);
	const std::string compiled_name = source.filename().string() + "c";
	const std::string cache_root = select_cache_root();
	return bfs::path(cache_root) / "yara_rules" / compiled_name;
}

void ensure_parent_dir(const bfs::path& path)
{
	boost::system::error_code ec;
	bfs::create_directories(path, ec);
}

} // namespace

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

	const bfs::path source(rule_filename);
	const bfs::path source_compiled = bfs::path(rule_filename + "c");
	const bfs::path cache_compiled = compiled_rules_path(rule_filename);

	if (is_up_to_date(cache_compiled, source)) {
		retval = yr_rules_load(cache_compiled.string().c_str(), &_rules);
	}
	else if (is_up_to_date(source_compiled, source)) {
		retval = yr_rules_load(source_compiled.string().c_str(), &_rules);
	}
	else {
		retval = yr_rules_load(rule_filename.c_str(), &_rules);
	}

	// Yara rules compiled with a previous Yara version. Delete and recompile.
	if (retval == ERROR_UNSUPPORTED_FILE_VERSION) {
		if (bfs::exists(cache_compiled)) {
			boost::filesystem::remove(cache_compiled);
		}
		if (bfs::exists(source_compiled)) {
			boost::filesystem::remove(source_compiled);
		}
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
	else if (retval == ERROR_INVALID_FILE || retval == ERROR_UNSUPPORTED_FILE_VERSION) // Uncompiled rules
	{
		if (yr_compiler_create(&_compiler) != ERROR_SUCCESS) {
			return false;
		}
		yr_compiler_set_callback(_compiler, compiler_callback, nullptr);
		FILE* rule_file = fopen(rule_filename.c_str(), "r");
		if (rule_file == nullptr) {
			return false;
		}
		bool ok = false;
		do {
			retval = yr_compiler_add_file(_compiler, rule_file, nullptr, rule_filename.c_str());
			if (retval != 0)
			{
				PRINT_ERROR << "Could not compile yara rules (" << retval << " error(s))." << std::endl;
				break;
			}
			retval = yr_compiler_get_rules(_compiler, &_rules);
			if (retval != ERROR_SUCCESS) {
				break;
			}

			// Save the compiled rules to improve load times.
			const bfs::path cache_dir = cache_compiled.parent_path();
			if (!cache_dir.empty()) {
				ensure_parent_dir(cache_dir);
			}
			retval = yr_rules_save(_rules, cache_compiled.string().c_str());
			if (retval != ERROR_SUCCESS) {
				PRINT_WARNING << "Could not save compiled Yara rules to " << cache_compiled.string()
				              << " (" << translate_error(retval) << ")." << std::endl;
			}

			ok = true;
			_current_rules = rule_filename;
		} while (false);

		res = ok;
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
