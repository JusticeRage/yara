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

#ifndef _MANAPE_DATA_H_
#define _MANAPE_DATA_H_

#include <stdint.h>

/**
 *	@brief	Some summary section information.
 */
typedef struct manape_section_t {
	uint32_t	section_start;
	uint32_t	section_size;
} manape_section;

/**
	The object which is passed to the Yara ManaPE module.
*/
typedef struct manape_data_t {
	uint32_t		entrypoint;
	manape_section*	sections;
	uint32_t		number_of_sections;
} manape_data;

#endif // !_MANAPE_DATA_H_d
