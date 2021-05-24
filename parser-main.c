

#include "Windows.h"
#include <iostream>



int main(int argc, char *argv[])
{
	
	PIMAGE_DOS_HEADER dos_header = {};
	HANDLE hFile, hFileMap;
	LPVOID fileData = NULL;

	if (argc < 2) {
		printf("Usage: %s <Address of PE file>\n", argv[0]);
		return -1;
	}

	hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hFile == INVALID_HANDLE_VALUE)
		return -1;

	hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, NULL);
	if (hFileMap == INVALID_HANDLE_VALUE)
		return -1;

	fileData = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

	dos_header = (PIMAGE_DOS_HEADER)fileData;
	printf("DOS HEADER\n");
	printf("\t0x%x\t\tMagic number\n", dos_header->e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", dos_header->e_cblp);
	printf("\t0x%x\t\tPages in file\n", dos_header->e_cp);
	printf("\t0x%x\t\tRelocations\n", dos_header->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", dos_header->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dos_header->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dos_header->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", dos_header->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", dos_header->e_sp);
	printf("\t0x%x\t\tInitial SP value\n", dos_header->e_sp);
	printf("\t0x%x\t\tChecksum\n", dos_header->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", dos_header->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", dos_header->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", dos_header->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", dos_header->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dos_header->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", dos_header->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", dos_header->e_lfanew);
	
	typedef unsigned long long QWORD;
	typedef unsigned long long *PQWORD;
	PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((QWORD)fileData + dos_header->e_lfanew); 

	printf("\nNT HEADERS\n");
	printf("\t%x\t\tSignature\n", nt_headers->Signature);

	// FILE_HEADER
	printf("\n\tFILE HEADER\n");
	printf("\t0x%x\t\tMachine\n", nt_headers->FileHeader.Machine);
	printf("\t0x%x\t\tNumber of Sections\n", nt_headers->FileHeader.NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", nt_headers->FileHeader.TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", nt_headers->FileHeader.PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", nt_headers->FileHeader.NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", nt_headers->FileHeader.SizeOfOptionalHeader);


	// Optional Header
	printf("\nOPTIONAL HEADER\n");
	printf("\t\t0x%x\t\tMagic\n", nt_headers->OptionalHeader.Magic);
	printf("\t\t0x%x\t\tLinker Ver. (Major)\n", nt_headers->OptionalHeader.MajorLinkerVersion);
	printf("\t\t0x%x\t\tLinker Ver. (Minor)\n", nt_headers->OptionalHeader.MinorLinkerVersion);
	printf("\t\t0x%x\t\tSize of Code\n", nt_headers->OptionalHeader.SizeOfCode);
	printf("\t\t0x%x\t\tSize of Initialized Data\n", nt_headers->OptionalHeader.SizeOfInitializedData);
	printf("\t\t0x%x\t\tSize of Unitialized Data\n", nt_headers->OptionalHeader.SizeOfUninitializedData);
	printf("\t\t0x%x\t\tEntry Point\n", nt_headers->OptionalHeader.AddressOfEntryPoint);
	printf("\t\t0x%x\t\tBase of Code\n", nt_headers->OptionalHeader.BaseOfCode);
	printf("\t\t0x%x\tImage Base\n", nt_headers->OptionalHeader.ImageBase);
	printf("\t\t0x%x\t\tSection Alignment\n", nt_headers->OptionalHeader.SectionAlignment);
	printf("\t\t0x%x\t\tFile Alignment\n", nt_headers->OptionalHeader.FileAlignment);
	printf("\t\t0x%x\t\tSection Alignment\n", nt_headers->OptionalHeader.SectionAlignment);
	printf("\t\t0x%x\t\tOS Ver. (Major)\n", nt_headers->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t\t0x%x\t\tOS Ver. (Minor)\n", nt_headers->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t\t0x%x\t\tImage Ver. (Major)\n", nt_headers->OptionalHeader.MajorImageVersion);
	printf("\t\t0x%x\t\tImage Ver. (Minor)\n", nt_headers->OptionalHeader.SectionAlignment);
	printf("\t\t0x%x\t\tSubsystem Ver. (Major)\n", nt_headers->OptionalHeader.MajorSubsystemVersion);
	printf("\t\t0x%x\t\tSubsystem Ver. (Minor)\n", nt_headers->OptionalHeader.MinorSubsystemVersion);
	printf("\t\t0x%x\t\tWin32 Version Value\n", nt_headers->OptionalHeader.Win32VersionValue);
	printf("\t\t0x%x\tSize of Image\n", nt_headers->OptionalHeader.SizeOfImage);
	printf("\t\t0x%x\t\tSize of Headers\n", nt_headers->OptionalHeader.SizeOfHeaders);
	printf("\t\t0x%x\t\tChecksum\n", nt_headers->OptionalHeader.CheckSum);
	printf("\t\t0x%x\t\tSubsystem\n", nt_headers->OptionalHeader.Subsystem);
	printf("\t\t0x%x\t\tDllCharacteristics\n", nt_headers->OptionalHeader.DllCharacteristics);
	printf("\t\t0x%x\tSize of Stack Reserve\n", nt_headers->OptionalHeader.SizeOfStackReserve);
	printf("\t\t0x%x\t\tSize of Stack Commit\n", nt_headers->OptionalHeader.SizeOfStackCommit);
	printf("\t\t0x%x\tSize of Head Reserve\n", nt_headers->OptionalHeader.SizeOfHeapReserve);
	printf("\t\t0x%x\t\tSize of Heap Commit\n", nt_headers->OptionalHeader.SizeOfHeapCommit);
	printf("\t\t0x%x\t\tLoader Flags\n", nt_headers->OptionalHeader.LoaderFlags);
	printf("\t\t0x%x\t\tNumber Of Rva And Sizes\n", nt_headers->OptionalHeader.NumberOfRvaAndSizes);


	typedef struct data_directory{
		DWORD VirtualAddress;
		DWORD Size;
		DWORD RawOffset;
		DWORD SectionVirtualAddress;
		QWORD SectionRawAddress;
	} data_directory;
	data_directory export_directory = {0};
	data_directory import_directory = {0};

	export_directory.VirtualAddress = (DWORD)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	export_directory.Size = (DWORD)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	
	import_directory.VirtualAddress = (DWORD)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	import_directory.Size = (DWORD)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	
	printf("\nData Directory\n");
	printf("\t\t%x\t\tImport Directory Virtual Address\n", import_directory.VirtualAddress);


	printf("\tSection Headers: \n");
	
	QWORD section_header_address = (QWORD)nt_headers + (QWORD)24 + (QWORD)nt_headers->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)section_header_address;
	QWORD rawOffset = NULL;
	for (int i = 1; i <= nt_headers->FileHeader.NumberOfSections; i++) {
		printf("\t\t%s\t\tVirtual Address:%x", section_header->Name,section_header->VirtualAddress);
		printf("\t\tRaw Address: 0x%x",section_header->PointerToRawData);
		printf("\t\tRaw Size:0x%x\n", section_header->SizeOfRawData);
		section_header = (PIMAGE_SECTION_HEADER)section_header_address + i;
		
		if (section_header->VirtualAddress <= import_directory.VirtualAddress && section_header->VirtualAddress > 0) {
			import_directory.RawOffset = section_header->PointerToRawData + (import_directory.VirtualAddress-section_header->VirtualAddress);
			import_directory.SectionVirtualAddress = section_header->VirtualAddress;
			import_directory.SectionRawAddress = (QWORD)fileData + section_header->PointerToRawData;
		}

		if (section_header->VirtualAddress <= export_directory.VirtualAddress && section_header->VirtualAddress > 0) {
			export_directory.RawOffset = section_header->PointerToRawData + (export_directory.VirtualAddress - section_header->VirtualAddress);
			export_directory.SectionVirtualAddress = section_header->VirtualAddress;
			export_directory.SectionRawAddress = (QWORD)fileData + section_header->PointerToRawData;
		}
	}

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR) ((QWORD)fileData + import_directory.RawOffset) ;
	printf("\tImport Table\n");
	

	for (; import_descriptor->Name != NULL; (PIMAGE_IMPORT_DESCRIPTOR)import_descriptor++) {
		char* dllname = (char*)((QWORD)import_directory.SectionRawAddress + (import_descriptor->Name - import_directory.SectionVirtualAddress));
		QWORD iat_RawAddress = (QWORD)import_directory.SectionRawAddress + (import_descriptor->FirstThunk - import_directory.SectionVirtualAddress);
		printf("\t\tDLL name: %s\t\t\n", dllname);

		PIMAGE_THUNK_DATA64 thunk = (PIMAGE_THUNK_DATA64)(iat_RawAddress);
		for (; thunk->u1.AddressOfData; (PIMAGE_THUNK_DATA)thunk++) {
			if (thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) {

				printf("\t\t\t\tOrdinal: %08x\n", thunk->u1.AddressOfData & ~IMAGE_ORDINAL_FLAG64);
			}
			else {
				printf("\t\t\t\t%s\t\t\n", (QWORD)import_directory.SectionRawAddress + (thunk->u1.AddressOfData - import_directory.SectionVirtualAddress) + 2);
			}
		}
	}
	

	printf("\n\n\tExport Table\n\n");
	if (export_directory.Size == 0) {
		printf("\t\t\t\tNo Export function");
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((QWORD)fileData + export_directory.RawOffset);

	PDWORD AddressOfNames = (PDWORD)(export_directory.SectionRawAddress + (image_export_directory->AddressOfNames - export_directory.SectionVirtualAddress));

	for (DWORD i = 0; i < image_export_directory->NumberOfNames; i++) {
		printf("\t\t\t\t%s\n", (char*)(export_directory.SectionRawAddress + (AddressOfNames[0]) - export_directory.SectionVirtualAddress));
	}

	return 0;
}
