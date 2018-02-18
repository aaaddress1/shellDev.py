title = \
"""
      _          _ _ _____             
     | |        | | |  __ \            
  ___| |__   ___| | | |  | | _____   __
 / __| '_ \ / _ \ | | |  | |/ _ \ \ / /
 \__ \ | | |  __/ | | |__| |  __/\ V / 
 |___/_| |_|\___|_|_|_____/ \___| \_/  
                                       
v1.0 by aaaddress1@chroot.org
"""

import subprocess
import re
import os
import sys
from optparse import OptionParser

shellDevHpp = \
"""
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;
typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
typedef struct _PROCESS_BASIC_INFORMATION64 {
	ULONG64 ExitStatus;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	ULONG64 BasePriority;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;
typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG64 ProcessParameters;
	ULONG64 SubSystemData;
	ULONG64 ProcessHeap;
	ULONG64 FastPebLock;
	ULONG64 AtlThunkSListPtr;
	ULONG64 IFEOKey;
	ULONG64 CrossProcessFlags;
	ULONG64 UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG64 ApiSetMap;
} PEB64, *PPEB64;
typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;
typedef struct _UNICODE_STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;
typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY64 HashLinks;
		ULONG64 SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG64 LoadedImports;
	};
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

# define FORCE_INLINE __attribute__((always_inline)) inline
# define NOINLINE __declspec(noinline)
# define shellFunc __attribute__((fastcall)) __attribute__((section("shell"))) NOINLINE

#define getModAddr(libraryName) (HMODULE)( \
	getModAddrByHash(modHash(libraryName)) \
	)

#define getFuncAddr(libraryAddress, functionName) (PVOID)( \
	getFuncAddrByHash(libraryAddress, modHash(functionName)) \
	)

void shellFunc shellEntry(void);

template<class T> struct func {
	explicit func(FARPROC ptr) : _ptr(ptr) {}
	operator T() { return reinterpret_cast<T>(_ptr); }
	FARPROC _ptr;
};

uint32_t shellFunc modHash(wchar_t *modName) {
	uint32_t buf = 0;
	while (*(modName++)) {
		buf += (*modName | 0x20);
		buf = (buf << 24 | buf >> (sizeof(uint32_t) * 8 - 24)); /* rotl */
	}
	return buf;
}

uint32_t shellFunc modHash(char *modName) {
	uint32_t buf = 0;
	while (*(modName++)) {
		buf += (*modName | 0x20);
		buf = (buf << 24 | buf >> (sizeof(uint32_t) * 8 - 24)); /* rotl */
	}
	return buf;
}

size_t shellFunc getModAddrByHash(uint32_t targetHash)
{
#ifdef _WIN64
	PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList); 
	PLIST_ENTRY curr = header->Flink;
	for (; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
		if (modHash(data->BaseDllName.Buffer) == targetHash)
			return data->DllBase;
	}
#else
	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	PLIST_ENTRY curr = header->Flink;
	for (; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
		if (modHash(data->BaseDllName.Buffer) == targetHash)
			return data->DllBase;
	}
#endif
	return 0;
}

size_t shellFunc getFuncAddrByHash(HMODULE module, uint32_t targetHash)
{
#if defined _WIN64
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
	PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);
	for (DWORD i = 0; i < ied->NumberOfNames; i++)
	{
		LPDWORD curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfNames + i * sizeof(DWORD));
		if (curName && (modHash((LPSTR)((LPBYTE)module + *curName)) == targetHash))
		{
			LPWORD pw = (LPWORD)(((LPBYTE)module) + ied->AddressOfNameOrdinals + i * sizeof(WORD));
			curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfFunctions + (*pw) * sizeof(DWORD));
			return ((size_t)module + *curName);
		}
	}
	return (size_t)0;
}
"""

def compileCtoAsmFile(cPath, asmPath):
	global mingwPath
	subprocess.call([
		os.path.join(mingwPath, 'gcc'), 
		'-fno-asynchronous-unwind-tables',
		'-s',
		'-O3',
		'-ffunction-sections',
		'-S',
		'-Wa,-R',
		'-Wa,-mintel',
		'-falign-functions=1',
		'-c', cPath,
		'-o', asmPath
	], cwd=mingwPath)

def jmpShellCodeEntry(inAsmPath, outAsmPath):
	with open(inAsmPath, 'r') as r:
		src = r.read()
		funcNameArr = re.findall(r'.globl[\t\x20]+(.+)', src, re.IGNORECASE)
		entryFunc = ''
		for eachFunc in funcNameArr:
			if 'shellEntry' in eachFunc:
				entryFunc = eachFunc

		with open(outAsmPath, 'w') as w:
			w.write('.section shell,"x"\r\ncall %s\r\nret \r\n' % entryFunc + src)

def genObjAsmBinary(inAsmPath, outObjectFilePath, outAsmRawBinPath):
	global mingwPath
	subprocess.call([
		os.path.join(mingwPath, 'as'), 
		'-c', inAsmPath,
		'-o', outObjectFilePath
	], cwd=mingwPath)
	subprocess.call([
		os.path.join(mingwPath, 'objcopy'), 
		'-O', 'binary',
		outObjectFilePath,
		'-j', 'shell',
		outAsmRawBinPath
	], cwd=mingwPath)

def arrayifyBinaryRawFile(asmRawBinPath):
	with open(asmRawBinPath, 'rb') as binary_file:
		data =binary_file.read()
		dataHexArr = ', '.join(['0x%02X' % ord(i) for i in data])
		dataHexArr = re.sub('(' + '0x\w\w, '*12 +')', r'\1\n', dataHexArr)
		retn = 'unsigned char shellcode[] = {\n%s };\r\n' % dataHexArr
		retn += 'unsigned int shellcode_size = %i;\n' % len(data)
		return retn

def genShellcode(cppPath, clearAfterRun):
	dir = os.getcwd()

	if len(os.path.dirname(cppPath)) == 0:
		cppPath = os.path.join(dir, cppPath)
		if not os.path.exists(cppPath):
			print('shellDev script not found at %s\n' % cppPath)
			sys.exit(1)

	print('[v] shellDev script at %s' % cppPath)
	preScriptPath = os.path.splitext(cppPath)[0]
	postScriptPath = os.path.splitext(cppPath)[1]

	cpp = preScriptPath + postScriptPath
	tmpcpp = preScriptPath + '_tmp' + postScriptPath
	asm = preScriptPath + 's'
	shellAsm = preScriptPath + '_shell.s'
	obj = preScriptPath + '.o'
	binraw = preScriptPath + '.bin'
	shelltxtOut = preScriptPath + '_shellcode.txt'
	with open(cpp, 'r') as i:
		script = i.read()
		script = script.replace('#include <shellDev>', shellDevHpp)
		with open(tmpcpp, 'w') as w:
			w.write(script)

	compileCtoAsmFile(tmpcpp, asm)
	jmpShellCodeEntry(asm, shellAsm)
	genObjAsmBinary(shellAsm, obj, binraw)

	with open(shelltxtOut, 'w') as w:
		w.write(arrayifyBinaryRawFile(binraw))
	print('shellcode saved at %s' % shelltxtOut)

	if clearAfterRun:
		os.remove(asm)
		os.remove(shellAsm)
		os.remove(obj)
		os.remove(tmpcpp)
		os.remove(binraw)

def chkExeExist(name, path):
	if os.path.exists(path):
		print '\t[v] %s exists!' % name
	else:
		print '\t[x] %s not found at %s' % (name, path)
		sys.exit(1)

def chkMinGwToolkit(usrInputMinGWPath):
	global mingwPath
	mingwPath = usrInputMinGWPath
	if not 'bin' in mingwPath:
		mingwPath = os.path.join(mingwPath, 'bin')
		if os.path.exists(mingwPath):
			print '[v] check mingw tool path: %s ' % mingwPath
		else:
			print '[x] sorry, mingw toolkit not found in %s' % mingwPath
	chkExeExist('gcc', os.path.join(mingwPath, 'gcc.exe'))
	chkExeExist('as', os.path.join(mingwPath, 'as.exe'))
	chkExeExist('objcopy', os.path.join(mingwPath, 'objcopy.exe'))
	print('')

if __name__ == "__main__":
	print(title)
	parser = OptionParser()
	parser.add_option("-s", "--src", dest="source",
	      help="shelldev c/c++ script path.", metavar="PATH")
	parser.add_option("-m", "--mgw", dest="mingwPath",
	      help="set mingw path, mingw path you select determine payload is 32bit or 64bit.", metavar="PATH")
	parser.add_option("--noclear",
	      action="store_true", dest="dontclear", default=False,
	      help="don't clear junk file after generate shellcode.")
	(options, args) = parser.parse_args()
	if options.source is None or options.mingwPath is None:
		parser.print_help()
	else:
		chkMinGwToolkit(options.mingwPath)
		genShellcode(options.source, not options.dontclear)