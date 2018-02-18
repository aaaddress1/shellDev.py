![螢幕快照 2018-02-18 上午10.55.26.png](resources/33032DBAA305F49DAAC4705D6967CB15.png)

## shellDev.py
A simple python script for building windows 32bit/64bit shellcode in C. 

## Preinstall
* Python 2.7 <https://www.python.org/download/releases/2.7/>
* MinGW-w64 <https://sourceforge.net/projects/mingw-w64/>

## shellDev Script Example: msg.cpp

```cpp
#include <shellDev>

void shellFunc shellEntry(void) {
    PVOID addr;

    char knl32[] = "kernel32.dll";
    char ldLibastr[] = "LoadLibraryA";
    addr = getFuncAddr(getModAddr(knl32), ldLibastr);
    func<decltype(&LoadLibraryA)> loadLibA((FARPROC)addr);

    char usr32[] = "user32.dll";
    char msgboxastr[] = "MessageBoxA";
    addr = getFuncAddr(loadLibA(usr32), msgboxastr);
    func<decltype(&MessageBoxA)> msgbox((FARPROC)addr);

    char msg[] = "top-level message here!";
    char title[] = "you must know it!";
    msgbox(0, msg, title, 0);
}
```

you can easily get module memory address by `getModAddr()` (like windows api `GetModuleHandleA`) and get function address by `getFuncAddr()` (like windows api `GetProcAddress`).

the foregoing example will be build in a large size shellcode (624 bytes), a better example:

```cpp
#include <shellDev>
void shellFunc shellEntry(void) {
	PVOID addr;

	char usr32[] = "user32.dll";
	HMODULE knl32Mod = (HMODULE)getModAddrByHash(/* kernel32.dll */0xb40d1235);
	addr = getFuncAddrByHash(knl32Mod, /* LoadLibraryA */0xee383d4a);
	func<decltype(&LoadLibraryA)> loadLibA((FARPROC)addr);

	HMODULE usr32Mod = loadLibA(usr32); 
	addr = getFuncAddrByHash(usr32Mod, /* MessageBoxA */0xf63a44d0);
	func<decltype(&MessageBoxA)> msgbox((FARPROC)addr);

	char msg[] = "adr big dick!!";
	char title[] = "you must know it!";
	msgbox(0, msg, title, 0);
}
```
using `getModAddrByHash()` and `getFuncAddrByHash()` instead of `getModAddr()` and `getFuncAddr()`, you can build smaller size shellcode (only 496 bytes). 

you can use `modHash()` (defined in [shellDev.hpp](shellDev.hpp)) to get string hash.
e.g. 
* modHash("kernel32.dll") = 0xb40d1235
* modHash("LoadLibraryA") = 0xee383d4a
* modHash("MessageBoxA") = 0xf63a44d0

*modHash(wchar_t[]) or modHash(char[]) is case-insensitive.*

```cpp
#include <shellDev>

PVOID shellFunc getUsr32Mod() {
	PVOID knl32Mod = getModAddrByHash(/* kernel32.dll */0xb40d1235);
	PVOID addr = getFuncAddrByHash
	(
		(HMODULE)knl32Mod, 
		/* LoadLibraryA */0xee383d4a
	);
	func<decltype(&LoadLibraryA)> loadLibA((FARPROC)addr);

	char usr32[] = "user32.dll";
	PVOID usr32Mod = loadLibA(usr32); 
	return usr32Mod;
}
void shellFunc shellEntry(void) {
	char msgboxastr[] = "MessageBoxA";
	PVOID addr = getFuncAddrByHash
	(
		(HMODULE)getUsr32Mod(),
		/* MessageBoxA */0xf63a44d0
	);
	func<decltype(&MessageBoxA)> msgbox((FARPROC)addr);

	char msg[] = "top-level message here!";
	char title[] = "you must know it!";
	msgbox(0, msg, title, 0);
}
```
you must define your own function in `shellFunc` calling convention if you want to declared a new function.

## Limitation

all variables should be defined as local variables, global variables will lead to crash. (the string parameters you pass to functions should be defined as local variables too)

## Usage

[![Demo on Youtube](http://img.youtube.com/vi/LAL2HCVkprU/0.jpg)](https://www.youtube.com/watch?v=LAL2HCVkprU&feature=youtu.be)

Building 32bit Windows shellcode:
`> python shellDev.py -m C:\MinGW\mingw32\ -s msg.cpp`

Building 62bit Windows shellcode:
`> python shellDev.py -m C:\MinGW\mingw64\ -s msg.cpp`

## Contact

* Twitter @aaaddress1
* aaaddress1@chroot.org
* www.facebook.com/aaaddress1
