/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: platform.h
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation; either version 2.1
* of the License, or  (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with noscrypt. If not, see http://www.gnu.org/licenses/.
*/

/*
*	Contains platform specific defintions
*/

#pragma once

#ifndef _NC_PLATFORM_H
#define _NC_PLATFORM_H

#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
	#define _NC_IS_WINDOWS
#elif defined(__linux__) || defined(__unix__) || defined(__posix__)
	#define _NC_IS_LINUX
#elif defined(__APPLE__) || defined(__MACH__)
	#define _NC_IS_MAC
#endif

/*
* Define supported inline defintions for various compilers 
* and C standards
*/

#if defined(_NC_IS_WINDOWS) || defined(inline) || defined(__clang__)
	#define _nc_fn_inline inline
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L /* C99 allows usage of inline keyword */
	#define _nc_fn_inline inline
#elif defined(__GNUC__) || defined(__GNUG__)
	#define _nc_fn_inline __inline__
#else
	#define _nc_fn_inline
	#pragma message("Warning: No inline keyword defined for this compiler")
#endif

#endif /* !_NC_PLATFORM_H */