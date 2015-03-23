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

#include <yara/modules/sgpe_data.h>
#include <yara/modules.h>


/**
 *	@brief	This module is a replacement for Yara's PE module. SpikeGuard already does all the PE parsing, so there
 *			is little point in bundling another PE parser. This module acts as a gateway between Yara and the data
 *			already parsed by SGPE.
 */
#define MODULE_NAME sgpe


begin_declarations;

declare_integer("ep");
declare_integer_array("sections");

end_declarations;

int module_initialize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_finalize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_load(
	YR_SCAN_CONTEXT* context,
	YR_OBJECT* module_object,
	void* module_data,
	size_t module_data_size)
{
	uint32_t i;

	if (module_data == NULL) {
		return ERROR_INVALID_ARGUMENT;
	}
	sgpe_data* pe_info = (sgpe_data*) module_data;
	set_integer(pe_info->entrypoint, module_object, "ep");
	for (i = 0 ; i < pe_info->number_of_sections ; ++i) {
		set_integer(pe_info->sections[i], module_object, "sections[%i]", i);
	}
	return ERROR_SUCCESS;
}

int module_unload(
	YR_OBJECT* module_object)
{
	return ERROR_SUCCESS;
}

#undef MODULE_NAME