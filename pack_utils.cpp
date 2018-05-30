#include "stdafx.h"
#include <winnt.h>
#include <stdlib.h>
#include <stdio.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pack.h"
#include "aplib.h"

PE pe;
//Internal dll calls
const char *dlls [] = {"kernel32.dll", ""};
const char *thunks [] = {"VirtualAlloc", "VirtualFree", "VirtualProtect", "GetProcAddress", "LoadLibraryA","RtlMoveMemory", ""};

int wsstrcpy(char *dest, const char *src)
{
	strcpy(dest,src);
	return strlen(dest);
}




void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe)
{
	DWORD idx = pe->int_headers.FileHeader.NumberOfSections;
	DWORD dwSectionSize = _section_size;
	pe->int_headers.FileHeader.NumberOfSections++;
	pe->m_sections = (isections*) realloc(pe->m_sections, pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
	memset(&pe->m_sections[idx], 0x00, sizeof(isections));
	pe->m_sections[idx].data = (BYTE*) malloc(align(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	pe->m_sections[idx].header.PointerToRawData = align(pe->m_sections[idx - 1].header.PointerToRawData + pe->m_sections[idx - 1].header.SizeOfRawData, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.VirtualAddress = align(pe->m_sections[idx - 1].header.VirtualAddress + pe->m_sections[idx - 1].header.Misc.VirtualSize, pe->int_headers.OptionalHeader.SectionAlignment);
	pe->m_sections[idx].header.SizeOfRawData = align(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.Misc.VirtualSize = dwSectionSize;
	pe->m_sections[idx].header.Characteristics  = 0xE0000020;
	sprintf((char*) pe->m_sections[idx].header.Name, "%s", sname);
	memset(pe->m_sections[idx].data, 0x00, align(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	memcpy(pe->m_sections[idx].data, _section, _section_size);
	pe->int_headers.OptionalHeader.AddressOfEntryPoint = pe->m_sections[idx].header.VirtualAddress + _entry_point_offset;
}

int pe_read(const char* filename, PE *pe)
{
	FILE *hFile = fopen(filename, "rb");
	if(hFile == NULL)
	{
		return 0;
	}
	fread(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);
	if(pe->m_dos.header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}
	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if(pe->m_dos.stub_size)
	{
		pe->m_dos.stub = (BYTE*) malloc(pe->m_dos.stub_size);
		fread(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	}
	fread(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);
	if(pe->int_headers.Signature != IMAGE_NT_SIGNATURE){
		return 0;
	}
	pe->m_sections = (isections*) malloc(pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
		fread(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);
	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
	{
		if(pe->m_sections[i].header.SizeOfRawData)
		{
			
			fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
			pe->m_sections[i].data = (BYTE*) malloc(pe->m_sections[i].header.SizeOfRawData);
			fread(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
		}
	}
	pe->EntryPoint = pe->int_headers.OptionalHeader.AddressOfEntryPoint + pe->int_headers.OptionalHeader.ImageBase;
	fclose(hFile);
	return 1;
}

int pe_write(const char* filename, PE *pe)
{
	FILE *hFile = fopen(filename, "wb");
	if(!hFile)
		return 0;
	fwrite(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);
	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if(pe->m_dos.stub_size)
    fwrite(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = NULL;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = NULL;
	pe->int_headers.OptionalHeader.SizeOfImage = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress + pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.Misc.VirtualSize;
	fwrite(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);
	fseek(hFile, pe->m_dos.header.e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);
	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
		fwrite(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);

	for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
	{
		if(pe->m_sections[i].header.SizeOfRawData)
		{
			fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
			fwrite(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
		}
	}
	fclose(hFile);
	return 1;
}

DWORD rvatoffset(DWORD Address);
int compress_file(char* argv)
{
	ZeroMemory(&pe,sizeof(PE));
	if(!pe_read(argv, &pe))
	{
		return 0;
	}
	char outfile[MAX_PATH] = {};
	lstrcpyA(outfile,argv);
	lstrcatA(outfile, ".packed.exe");
	CopyFile(argv, outfile, false);

	/* Initialize internal dll calls */
	pe.dlls = (char**)malloc(sizeof(dlls));
	for(int i = 0; i < sizeof(dlls) / 4; i++)
	{
		pe.dlls[i] = (char*)malloc(strlen(dlls[i]));
		strcpy(pe.dlls[i], dlls[i]);
	}
	pe.thunks = (char**)malloc(sizeof(thunks));
	for(int i = 0; i < sizeof(thunks) / 4; i++)
	{
		pe.thunks[i] = (char*)malloc(strlen(thunks[i]));
		strcpy(pe.thunks[i], thunks[i]);
	}

	/* Calculate the space we need for dll calls */
	char **_dlls = pe.dlls;
	char **_thunks = pe.thunks;
	pe.sdllimports = sizeof(IMAGE_IMPORT_DESCRIPTOR); //zero import space
	while(*(*_dlls))
	{
		pe.sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //import space
		pe.sdllimports += strlen(*_dlls); //import name space
		pe.sdllimports += sizeof(DWORD); //zero thunk space
		while(*(*_thunks))
		{
			pe.sdllimports += sizeof(DWORD); //thunk space
			pe.sdllimports += sizeof(WORD) + strlen(*_thunks); //thunk hint + name space
			_thunks++;
		}
		_thunks++;
		_dlls++;
	}

	DWORD diff = 0; //General section offset difference
	DWORD carray = 0; //Section compression tracker

	pe.comparray = malloc(sizeof(DWORD));
	for(int i = 0; i < pe.int_headers.FileHeader.NumberOfSections; i++)
	{
		if(pe.m_sections[i].header.SizeOfRawData)
		{
			pe.m_sections[i].header.PointerToRawData -= diff;
			//Resources
			if(pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == pe.m_sections[i].header.VirtualAddress)
			{
				IMAGE_RESOURCE_DIRECTORY *rescdir =(IMAGE_RESOURCE_DIRECTORY*)pe.m_sections[i].data;
				pe.rescaddress = (DWORD)pe.m_sections[i].data;
				DWORD baseresc = 0;
				DWORD numentries = 0;
				pe.cuncompresource = 0;
				pe.uncompresource = NULL;
				pe.suncompresource = NULL;
				
				IMAGE_RESOURCE_DIRECTORY_ENTRY *rescdirentry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((DWORD)pe.rescaddress + sizeof(IMAGE_RESOURCE_DIRECTORY));
				numentries = rescdir->NumberOfIdEntries + rescdir->NumberOfNamedEntries;

				for(int j = 0;j < numentries; ++j)
				{
					IMAGE_RESOURCE_DIRECTORY *_rescdir = (IMAGE_RESOURCE_DIRECTORY*)(pe.rescaddress + LOWORD(rescdirentry->OffsetToData));
					IMAGE_RESOURCE_DIRECTORY_ENTRY *_rescdirentry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pe.rescaddress + LOWORD(rescdirentry->OffsetToData) + sizeof(IMAGE_RESOURCE_DIRECTORY));
					DWORD _numentries = _rescdir->NumberOfIdEntries + _rescdir->NumberOfNamedEntries;
					for(int k = 0;k < _numentries; ++k)
					{
						IMAGE_RESOURCE_DIRECTORY *__rescdir = (IMAGE_RESOURCE_DIRECTORY*)(pe.rescaddress + LOWORD(_rescdirentry->OffsetToData));
						IMAGE_RESOURCE_DIRECTORY_ENTRY *__rescdirentry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pe.rescaddress + LOWORD(_rescdirentry->OffsetToData) + sizeof(IMAGE_RESOURCE_DIRECTORY));
						IMAGE_RESOURCE_DATA_ENTRY *rescdatentry = (IMAGE_RESOURCE_DATA_ENTRY*)(pe.rescaddress + __rescdirentry->OffsetToData);

						if(!j && !k)
						{
							baseresc = rescdatentry->OffsetToData - pe.m_sections[i].header.VirtualAddress;
						}
						if(rescdirentry->Name == (DWORD)RT_ICON || rescdirentry->Name == (DWORD)RT_VERSION || rescdirentry->Name == (DWORD)RT_GROUP_ICON 
							|| rescdirentry->Name == (DWORD)RT_MANIFEST)
						{
							pe.cuncompresource++;
							pe.suncompresource += rescdatentry->Size;
							pe.uncompresource = (uncomresc*) realloc(pe.uncompresource, pe.cuncompresource * sizeof(uncomresc));
							pe.uncompresource[pe.cuncompresource - 1].rescdata = malloc(rescdatentry->Size);
							memcpy(pe.uncompresource[pe.cuncompresource - 1].rescdata, (LPVOID)rvatoffset(rescdatentry->OffsetToData), rescdatentry->Size);
							memset((LPVOID)rvatoffset(rescdatentry->OffsetToData), 0x00, rescdatentry->Size);
							pe.uncompresource[pe.cuncompresource - 1].rescinfo = (DWORD)rescdatentry - pe.rescaddress;
						}
						++_rescdirentry;
					}
					++rescdirentry;
				}



				BYTE *workmem    = (BYTE*)malloc(aP_workmem_size(pe.m_sections[i].header.SizeOfRawData - baseresc));
				pe.m_sections[i].cdata = (BYTE*)malloc(aP_max_packed_size(pe.m_sections[i].header.SizeOfRawData - baseresc));
				pe.m_sections[i].csize = aP_pack((BYTE*)((DWORD)pe.m_sections[i].data + baseresc),pe.m_sections[i].cdata,pe.m_sections[i].header.SizeOfRawData - baseresc, workmem, NULL, NULL);
				if(!pe.m_sections[i].cdata)
				{
					return 0;
				}
				carray++;
				pe.scomparray = sizeof(DWORD) + carray * sizeof(compdata);
				pe.comparray = realloc(pe.comparray, pe.scomparray);

				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].src = (LPVOID)(pe.m_sections[i].header.VirtualAddress + baseresc);
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData - baseresc;

				pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, pe.m_sections[i].csize + baseresc);
				pe.rescaddress = (DWORD)pe.m_sections[i].data;
				memcpy((LPVOID)((DWORD)pe.m_sections[i].data + baseresc), pe.m_sections[i].cdata, pe.m_sections[i].csize);
				pe.m_sections[i].csize = align(pe.m_sections[i].csize + baseresc, pe.int_headers.OptionalHeader.FileAlignment);
				diff += pe.m_sections[i].header.SizeOfRawData - pe.m_sections[i].csize;
				pe.m_sections[i].header.SizeOfRawData = pe.m_sections[i].csize;
				free(pe.m_sections[i].cdata);
				free(workmem);
			}
			//other
			//preserve TLS callbacks if they are there
			//otherwise, compress
		//	if (pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != pe.m_sections[i].header.VirtualAddress &&
			//	pe.int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != pe.m_sections[i].header.VirtualAddress)
			else
			{
				BYTE *workmem    = (BYTE*)malloc(aP_workmem_size(pe.m_sections[i].header.SizeOfRawData));
				pe.m_sections[i].cdata = (BYTE*)malloc(aP_max_packed_size(pe.m_sections[i].header.SizeOfRawData));
				pe.m_sections[i].csize = aP_pack((BYTE*)((DWORD)pe.m_sections[i].data),pe.m_sections[i].cdata,pe.m_sections[i].header.SizeOfRawData, workmem, NULL, NULL);
				if(!pe.m_sections[i].cdata)
				{
					return 0;
				}
				carray++;
				pe.scomparray = sizeof(DWORD) + carray * sizeof(compdata);
				pe.comparray = realloc(pe.comparray, pe.scomparray);
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].src = (LPVOID)pe.m_sections[i].header.VirtualAddress;
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].clen = pe.m_sections[i].csize;
				((compdata*)((DWORD)pe.comparray + sizeof(DWORD)))[carray - 1].nlen = pe.m_sections[i].header.SizeOfRawData;
				pe.m_sections[i].data = (BYTE*)realloc(pe.m_sections[i].data, pe.m_sections[i].csize);
				memcpy(pe.m_sections[i].data, pe.m_sections[i].cdata, pe.m_sections[i].csize);
				pe.m_sections[i].csize = align(pe.m_sections[i].csize, pe.int_headers.OptionalHeader.FileAlignment);
				diff += pe.m_sections[i].header.SizeOfRawData - pe.m_sections[i].csize;
				pe.m_sections[i].header.SizeOfRawData = pe.m_sections[i].csize;
				free(pe.m_sections[i].cdata);
				free(workmem);
			}
			
		}
	}
	*((DWORD*)pe.comparray) = carray;

	pointers p;
	ZeroMemory(&p,sizeof(pointers));
	functions(&p, &pe);
	if(!pe_write(outfile, &pe))
	return 1;
	return 0;
}

DWORD rvatoffset(DWORD Address) //We need this function for several compressed executables
{
	int i;
	for(i = 0; i < pe.int_headers.FileHeader.NumberOfSections; i++)
	{
		if(pe.m_sections[i].header.SizeOfRawData && Address &&
			Address >= pe.m_sections[i].header.VirtualAddress &&
			Address <= pe.m_sections[i].header.VirtualAddress + pe.m_sections[i].header.SizeOfRawData)
			break;
	}
	return ((DWORD)pe.m_sections[i].data + Address - pe.m_sections[i].header.VirtualAddress);
}
