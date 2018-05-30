/* pecrypt.h --

   This file is part of the "PE Maker".

   Copyright (C) 2005-2006 Ashkbiz Danehkar
   All Rights Reserved.

   "PE Maker" library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYRIGHT.TXT.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   yodap's Forum:
   http://yodap.sourceforge.net/forum/

   yodap's Site:
   http://yodap.has.it
   http://yodap.cjb.net
   http://yodap.sourceforge.net

   Ashkbiz Danehkar
   <ashkbiz@yahoo.com>
*/
#pragma once

typedef struct dos_section
{
	IMAGE_DOS_HEADER header;
	DWORD stub_size;
	BYTE *stub;
};

typedef struct isections
{
	IMAGE_SECTION_HEADER header;
	BYTE *data;
	DWORD csize;
	BYTE *cdata;
};

typedef struct dllexps
{
	IMAGE_EXPORT_DIRECTORY expdir;
	char **Names;
	DWORD *Functions;
	WORD *NameOrdinals;
};

typedef struct uncomresc
{
	LPVOID rescdata;
	DWORD rescinfo;
};

typedef struct PE
{
	DWORD EntryPoint;
	dos_section m_dos;
	LPVOID comparray;
	DWORD scomparray;
	char **dlls;
	char **thunks;
	DWORD sdllimports;
	DWORD rescaddress;
	uncomresc *uncompresource;
	DWORD cuncompresource;
	DWORD suncompresource;
	IMAGE_NT_HEADERS int_headers;
	isections *m_sections;
};
#define align(_size, _base_size) \
	(((_size + _base_size - 1) / _base_size) * _base_size)
#define addr(address) \
	((DWORD)pe.m_sections[i].data + (address - pe.m_sections[i].header.VirtualAddress))


typedef void (_stdcall *tmentry)(LPVOID);
typedef void (_stdcall *trestore)(LPVOID);
typedef WINBASEAPI PVOID (WINAPI **tVirtualAlloc)(PVOID,DWORD,DWORD,DWORD);
typedef WINBASEAPI PVOID (WINAPI **tRtlMoveMemory)(PVOID,PVOID,DWORD);
typedef WINBASEAPI BOOL (WINAPI **tVirtualFree)(PVOID,DWORD,DWORD);
typedef WINBASEAPI BOOL (WINAPI **tVirtualProtect)(PVOID,DWORD,DWORD,PDWORD);
typedef WINBASEAPI FARPROC (WINAPI **tGetProcAddress)(HINSTANCE,LPCSTR);
typedef WINBASEAPI HINSTANCE (WINAPI **tLoadLibraryA)(LPCSTR);

typedef int (_cdecl *tdecomp) (LPVOID, DWORD, LPVOID, DWORD);

typedef struct compdata
{
	LPVOID src;
	DWORD clen;
	DWORD nlen;
};

typedef struct pointers
{
	BYTE opcode[18];
	tVirtualAlloc VirtualAlloc;
	tVirtualFree VirtualFree;
	tVirtualProtect VirtualProtect;
	tGetProcAddress GetProcAddress;
	tLoadLibraryA LoadLibraryA;
	tRtlMoveMemory copymem;
	tmentry mentry;
	trestore restore;
	tdecomp decomp;
	DWORD ocompdata;
	DWORD ImageBase;
	DWORD OriginalImports;
	DWORD OriginalImports_Size;
	bool Loaded;
};

void construct(pointers *p, PE *pe, DWORD sfunc[2]);
int compress_file(char* argv);
void functions(pointers *pt, PE *pe);
int pe_read(const char* filename, PE *pe);
int pe_write(const char* filename, PE *pe);
void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe);
void CryptFile(int(__cdecl *callback) (unsigned int, unsigned int),char *filenameload);
BYTE * comp(BYTE* input, int in_size, int * out_size);