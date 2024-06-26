#include <windows.h>
#include <windns.h>
#include "mydll.h"
#include <stdio.h>
typedef struct
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} myfile_header;

typedef struct
{
    BYTE Name[8];
    union
    {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} mysection_header;

int my_strcmp(char *one, char *two)
{
    int index = 0;
    while (one[index] != NULL && two[index] != NULL)
    {
        if (one[index] != two[index])
            return 0;
        index += 1;
    }
    return 1;
}

void parse_export_section(DWORD export_section_start_offset, DWORD edata_virtual_address)
{
    DWORD characteristics = *(DWORD *)(mydll + export_section_start_offset);
    DWORD time_date_stamp = *(DWORD *)(mydll + export_section_start_offset + 0x4);
    WORD major_version = *(WORD *)(mydll + export_section_start_offset + 0x08);
    WORD minor_version = *(WORD *)(mydll + export_section_start_offset + 0x0a);
    DWORD name = *(DWORD *)(mydll + export_section_start_offset + 0x0c);
    DWORD base = *(DWORD *)(mydll + export_section_start_offset + 0x10);
    DWORD number_of_functions = *(DWORD *)(mydll + export_section_start_offset + 0x14);
    DWORD number_of_names = *(DWORD *)(mydll + export_section_start_offset + 0x18);
    DWORD address_of_functions = *(DWORD*)(mydll + export_section_start_offset + 0x1c);
    DWORD address_of_names = *(DWORD*)(mydll + export_section_start_offset + 0x20);
    DWORD address_of_name_ordinals = *(DWORD *)(mydll + export_section_start_offset + 0x24);
    printf("\t\t[0x%08x][#] Characteristics: 0x%08x\n", export_section_start_offset + 0x4, characteristics);
    printf("\t\t[0x%08x][#] TimeDateStamp: 0x%08x\n", export_section_start_offset + 0x4, time_date_stamp);
    printf("\t\t[0x%08x][#] MajorVersion: 0x%04x\n", export_section_start_offset + 0x08, major_version);
    printf("\t\t[0x%08x][#] MinorVersion: 0x%04x\n", export_section_start_offset + 0x0a, minor_version);
    printf("\t\t[0x%08x][#] Name Ptr: 0x%08x\n", export_section_start_offset + 0x0c, name);
    printf("\t\t[0x%08x][#] Base: 0x%08x\n", export_section_start_offset + 0x10, base);
    printf("\t\t[0x%08x][#] NumberOfFunctions: 0x%08x\n", export_section_start_offset + 0x14, number_of_functions);
    printf("\t\t[0x%08x][#] NumberOfNames: 0x%08x\n", export_section_start_offset + 0x18, number_of_names);
    printf("\t\t[0x%08x][#] AddressOfFunctions: 0x%08x\n", export_section_start_offset + 0x1c, address_of_functions);
    printf("\t\t[0x%08x][#] AddressOfNames: 0x%08x\n", export_section_start_offset + 0x20, address_of_names);
    printf("\t\t[0x%08x][#] AddressOfNameOrdinals: 0x%04x\n", export_section_start_offset + 0x24, address_of_name_ordinals);

    DWORD functions_start_offset = (QWORD)address_of_functions - edata_virtual_address + export_section_start_offset;
    DWORD names_start_offset = (QWORD)address_of_names - edata_virtual_address + export_section_start_offset;
    DWORD name_ordinals_start_offset = (QWORD)address_of_name_ordinals - edata_virtual_address + export_section_start_offset;
    printf("\t\t\t\t[#] file offset of AddressOfFunctions: 0x%08x\n", functions_start_offset);
    printf("\t\t\t\t[#] file offset of AddressOfNames: 0x%08x\n", names_start_offset);
    printf("\t\t\t\t[#] file offset of AddressOfNameOrdinals: 0x%08x\n", name_ordinals_start_offset);


    for (int i = 0; i < number_of_functions; i++)
    {
        DWORD func_name_file_offset = *(DWORD*)(mydll + names_start_offset + sizeof(DWORD)*i) - edata_virtual_address + export_section_start_offset;
        DWORD func_code_file_offset = *(DWORD*)(mydll + functions_start_offset + sizeof(DWORD)*i) - edata_virtual_address + export_section_start_offset;
        printf("\t\t\t\t[0x%016x] %s *** code at [0x%016x]\n", func_name_file_offset, (mydll + func_name_file_offset), func_code_file_offset);
    }
}
void parse_sections_header(WORD number_of_sections, DWORD section_header_start_offset)
{
    DWORD current_section_header_start_offset = section_header_start_offset;
    for (int i = 0; i < number_of_sections; i++)
    {

        mysection_header header = *(mysection_header *)(mydll + current_section_header_start_offset);

        printf("[*] Section Header: %s\n", header.Name);
        printf("\t[+] VirtualAddress: 0x%08x\n", header.VirtualAddress);
        printf("\t[+] SizeOfRawData: 0x%08x\n", header.SizeOfRawData);
        printf("\t[+] PointerToRawData: 0x%08x\n", header.PointerToRawData);
        printf("\t[+] PointerToRelocations: 0x%08x\n", header.PointerToRelocations);
        printf("\t[+] PointerToLinenumbers: 0x%08x\n", header.PointerToLinenumbers);
        printf("\t[+] NumberOfRelocations: 0x%04x\n", header.NumberOfRelocations);
        printf("\t[+] NumberOfLinenumbers: 0x%04x\n", header.NumberOfLinenumbers);
        printf("\t[+] Characteristics: 0x%08x\n", header.Characteristics);

        if (my_strcmp(header.Name, ".edata"))
        {
            parse_export_section(header.PointerToRawData, header.VirtualAddress);
        }
        current_section_header_start_offset += 0x28; // 0x28: size of section_header
    }
}

int main()
{
    int e_lfanew_offset = 0x3c;
    // DWORD e_lfanew = mydll[e_lfanew_offset + 0x3] << 24 | mydll[e_lfanew_offset + 0x2] << 16 | mydll[e_lfanew_offset + 0x1] << 8 | mydll[e_lfanew_offset];
    DWORD e_lfanew = *(DWORD *)(mydll + e_lfanew_offset);
    DWORD pe_header_start_offset = e_lfanew;
    DWORD file_header_start_offset = pe_header_start_offset + 0x04; //
    // SizeOfOptionalHeader: file_header + (Machine word) + (NumberOfSections word) + (TimeDateStamp dword) + (PointerToSymbolTable dword) + (NumberOfSymbols dword);
    DWORD size_of_optional_header_start_offset = file_header_start_offset + 0x02 + 0x02 + 0x04 + 0x04 + 0x04;
    // WORD size_of_optional_header_value = mydll[size_of_optional_header_start_offset + 1] << 8 | mydll[size_of_optional_header_start_offset];
    WORD size_of_optional_header_value = *(WORD *)(mydll + size_of_optional_header_start_offset);
    DWORD number_of_sections_start_offset = file_header_start_offset + 0x02;
    // WORD number_of_sections_value = mydll[number_of_sections_start_offset + 0x01] << 8 | mydll[number_of_sections_start_offset];
    WORD number_of_sections_value = *(WORD *)(mydll + number_of_sections_start_offset);
    DWORD optional_header_start_offset = file_header_start_offset + sizeof(myfile_header);
    DWORD section_header_start_offset = optional_header_start_offset + size_of_optional_header_value;
    printf("[+] optional header start offset:%08x \n", optional_header_start_offset);
    printf("[+] SizeOfOptionalHeaderStart:%08x ,SizeOfOptionalHeader: %04x\n", size_of_optional_header_start_offset, size_of_optional_header_value);
    parse_sections_header(number_of_sections_value, section_header_start_offset);
}