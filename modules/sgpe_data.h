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

#ifndef _SGPE_DATA_H
#define _SGPE_DATA_H

#include <stdint.h>

/**
The object which is passed to the Yara SGPE module.
*/
typedef struct sgpe_data_t {
	uint32_t	entrypoint;
	uint32_t*	sections;
	uint32_t	number_of_sections;
} sgpe_data;

#endif // !_SGPE_DATA_H