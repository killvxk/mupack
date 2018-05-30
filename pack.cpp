#include "stdafx.h"
#include <winnt.h>
#include <stdlib.h>
#include <stdio.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pack.h"
#include "aplib.h"

#pragma comment (lib, "aplib.lib")

#ifdef __cplusplus
extern "C" {
#endif
DWORD _cdecl depack_aplib(PVOID,DWORD,PVOID,DWORD);
DWORD _cdecl depack_aplibend();
#ifdef __cplusplus
}
#endif 



void CryptFile(int(__cdecl *callback1) (unsigned int, unsigned int),char *filenameload)
{
	callback1(0,0);
	int compress = compress_file(filenameload);
	if (!compress)
	{
		callback1(100,0);
	}
	else
	{
		callback1(0,0);
	}
}


//----------------------------------------------------------------
// PE STUB IN HERE!!!!!
//----------------------------------------------------------------
void restore(pointers *p)
{
	IMAGE_IMPORT_DESCRIPTOR *Imports;
	IMAGE_IMPORT_BY_NAME *iNames;
	DWORD dwThunk;
	DWORD *Thunk;
	DWORD *Function;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(p->ImageBase + p->OriginalImports);
	while(Imports->Name)
	{
		HINSTANCE Lib = (*p->LoadLibraryA)((const char*)(Imports->Name + p->ImageBase));
		dwThunk = Imports->OriginalFirstThunk ? Imports->OriginalFirstThunk : Imports->FirstThunk;
		Thunk = (DWORD*)(dwThunk + p->ImageBase);
		dwThunk = Imports->FirstThunk;
		while(*Thunk)
		{
			iNames = (IMAGE_IMPORT_BY_NAME*)(*Thunk + p->ImageBase);
			if(*Thunk & IMAGE_ORDINAL_FLAG)
			{
				Function = (DWORD*)(p->ImageBase + dwThunk);
				*Function = (DWORD)((*p->GetProcAddress)(Lib, (char*)LOWORD(*Thunk)));
			}
			else
			{
				Function = (DWORD*)(p->ImageBase + dwThunk);
				*Function = (DWORD)((*p->GetProcAddress)(Lib, (char*)iNames->Name));
			}
			dwThunk += sizeof(DWORD);
			Thunk++;
		}

		Imports++;
	}
}
void erestore(void){}
#pragma optimize ("gst",off)
void mentry(pointers *p)
{
		DWORD OldP= NULL;
		DWORD carray = *((DWORD*)p->ocompdata);
		compdata *cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));
		for(int i = 0; i < carray; i++)
		{
			DWORD* ucompd = (DWORD*)(*p->VirtualAlloc)(NULL, cmpdata->nlen, MEM_COMMIT, PAGE_READWRITE);
			DWORD uncompressed = (*p->decomp)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src),cmpdata->clen,ucompd,cmpdata->nlen);
			
			(*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src), cmpdata->nlen , PAGE_EXECUTE_READWRITE, &OldP);
			(*p->copymem)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src),ucompd, cmpdata->nlen );
			(*p->VirtualFree)(ucompd, 0, MEM_RELEASE);
			cmpdata++;
		}
		p->restore(p);
}
void ementry(void){} 
#pragma optimize ("gst",on)
//-----------------------------------------------------------------
// PE ENDS HERE
//----------------------------------------------------------------

void functions(pointers *p, PE *pe)
{
	DWORD psize, sfunc[3];
	sfunc[0] = (DWORD)&ementry - (DWORD)&mentry;
	sfunc[1] = (DWORD)&erestore - (DWORD)&restore;
	sfunc[2] = (DWORD)&depack_aplibend - (DWORD)&depack_aplib;
	psize = sfunc[0] + sfunc[1] + sfunc[2] + sizeof(pointers) + pe->scomparray + pe->suncompresource + pe->sdllimports;
	LPVOID psection = malloc(psize);
	memset(psection, 0x00, psize);

	p->mentry = (tmentry)((DWORD)psection + sizeof(pointers));
	p->restore = (tmentry)((DWORD)psection + sizeof(pointers) + sfunc[0]);
	p->decomp = (tdecomp)((DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1]);
	p->ocompdata = (DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2];

	memcpy(psection, p, sizeof(pointers));
	memcpy((LPVOID)p->mentry, (LPVOID)&mentry, sfunc[0]);
	memcpy((LPVOID)p->restore, (LPVOID)&restore, sfunc[1]);
	memcpy((LPVOID)p->decomp, (LPVOID)depack_aplib, sfunc[2]);
	memcpy((LPVOID)p->ocompdata, pe->comparray, pe->scomparray);

	DWORD puncomp = (DWORD)psection + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2] + pe->scomparray;
	pe->suncompresource = NULL;
	for(int i = 0; i <pe->cuncompresource; i++)
	{
		int size =  ((IMAGE_RESOURCE_DATA_ENTRY*)(pe->uncompresource[i].rescinfo +pe->rescaddress))->Size;
		memmove((LPVOID)(puncomp + pe->suncompresource), pe->uncompresource[i].rescdata,size);
		pe->suncompresource += size;
	}

	AddSection(".ML", psection, psize, NULL, pe);
	construct((pointers*) pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data, pe, sfunc);
}

void construct(pointers *pt, PE *pe, DWORD sfunc[3])
{
	DWORD vaddress = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress;
	DWORD pointer = pe->int_headers.OptionalHeader.ImageBase + vaddress;
	DWORD entry = pe->int_headers.OptionalHeader.ImageBase + vaddress + sizeof(pointers);
	pt->opcode[0] = 0x68; //push pointers struct to stack
	memcpy(&pt->opcode[1], &pointer, sizeof(DWORD));
	pt->opcode[5] = 0xB8; //mov eax entry point
	memcpy(&pt->opcode[6], &entry, sizeof(DWORD));
	pt->opcode[10] = 0xFF; pt->opcode[11] = 0xD0; //call eax
	pt->opcode[12] = 0xB8; //mov eax real entry point
	memcpy(&pt->opcode[13], &pe->EntryPoint, sizeof(DWORD));
	pt->opcode[17] = 0xFF; pt->opcode[18] = 0xE0; //jump eax
	pt->Loaded = false;
	pt->mentry = (tmentry)entry;
	pt->restore = (trestore)(entry + sfunc[0]);
	pt->decomp = (tdecomp)(entry + sfunc[0] + sfunc[1]);
	pt->ocompdata = entry + sfunc[0] + sfunc[1] + sfunc[2];
	DWORD puncomp = entry + sfunc[0] + sfunc[1] + sfunc[2] + pe->scomparray - pe->int_headers.OptionalHeader.ImageBase;
	pe->suncompresource = NULL;
	for(int i = 0; i < pe->cuncompresource; i++)
	{
		((IMAGE_RESOURCE_DATA_ENTRY*)(pe->uncompresource[i].rescinfo + pe->rescaddress))->OffsetToData = puncomp + pe->suncompresource;
		pe->suncompresource += ((IMAGE_RESOURCE_DATA_ENTRY*)(pe->uncompresource[i].rescinfo + pe->rescaddress))->Size;
	}

	DWORD pimports = (DWORD)pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].data + sizeof(pointers) + sfunc[0] + sfunc[1] + sfunc[2] + pe->scomparray + pe->suncompresource ;
	DWORD pimportsrva = entry + sfunc[0] + sfunc[1] + sfunc[2] + pe->scomparray + pe->suncompresource - pe->int_headers.OptionalHeader.ImageBase;

	char **_dlls = pe->dlls;
	char **_thunks = pe->thunks;
	IMAGE_IMPORT_DESCRIPTOR *Imports = NULL;
	DWORD *Thunks = NULL;

	pe->sdllimports = 0;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(pimports);
	while(*(*_dlls))
	{
		pe->sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //imports
		_dlls++;
	}
	pe->sdllimports += sizeof(IMAGE_IMPORT_DESCRIPTOR); //zero import

	_dlls = pe->dlls;
	Thunks = (DWORD*)(pimports + pe->sdllimports);

	DWORD *internals = (DWORD*)(&pt->VirtualAlloc);

	while(*(*_dlls))
	{
		Imports->FirstThunk = pimportsrva + pe->sdllimports;
		while(*(*_thunks))
		{
			*internals = pe->int_headers.OptionalHeader.ImageBase + pimportsrva + pe->sdllimports;
			pe->sdllimports += sizeof(DWORD); //thunks
			_thunks++;
			internals++;
		}
		pe->sdllimports += sizeof(DWORD); //zero thunk
		_thunks++;
		_dlls++;
		Imports++;
	}

	_dlls = pe->dlls;
	_thunks = pe->thunks;
	Imports = (IMAGE_IMPORT_DESCRIPTOR*)(pimports);
	while(*(*_dlls))
	{
		Imports->Name = pimportsrva + pe->sdllimports;
		strcpy((char*)(pimports + pe->sdllimports), *_dlls);
		pe->sdllimports +=  strlen((char*)*_dlls);//import names
		while(*(*_thunks))
		{
			*Thunks = pimportsrva + pe->sdllimports;
			pe->sdllimports += sizeof(WORD); //thunk hints
			strcpy((char*)(pimports + pe->sdllimports), *_thunks);
			pe->sdllimports +=  strlen((char*)*_thunks);//import names
			_thunks++;
			Thunks++;
		}
		_thunks++;
		_dlls++;
		Imports++;
		Thunks++;
	}
	pt->OriginalImports = pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pimportsrva;
	pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = pe->sdllimports;
	pt->ImageBase = pe->int_headers.OptionalHeader.ImageBase;
}


