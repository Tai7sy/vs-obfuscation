#pragma once
#ifndef OBFS_STRING_FUNC
#define OBFS_STRING_FUNC
#include <stdint.h>

//-------------------------------------------------------------//
// "Malware related compile-time hacks with C++11" by LeFF   //
// You can use this code however you like, I just don't really //
// give a shit, but if you feel some respect for me, please //
// don't cut off this comment when copy-pasting... ;-)       //
//-------------------------------------------------------------//

////////////////////////////////////////////////////////////////////
template <int X> struct EnsureCompileTime {
	enum : int {
		Value = X
	};
};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
//Use Compile-Time as Myseed
#define Myseed ((__TIME__[7] - '0') * 1  + (__TIME__[6] - '0') * 10  + \
                  (__TIME__[4] - '0') * 60   + (__TIME__[3] - '0') * 600 + \
                  (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
constexpr int LinearCongruentGenerator(int Rounds) {
	return 1013904223 + 1664525 * ((Rounds> 0) ? LinearCongruentGenerator(Rounds - 1) : Myseed & 0xFFFFFFFF);
}
#define Random() EnsureCompileTime<LinearCongruentGenerator(10)>::Value //10 Rounds
#define RandomNumber(Min, Max) (Min + (Random() % (Max - Min + 1)))
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
template <int... Pack> struct IndexList {};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
template <typename IndexList, int Right> struct Append;
template <int... Left, int Right> struct Append<IndexList<Left...>, Right> {
	typedef IndexList<Left..., Right> Result;
};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
template <int N> struct ConstructIndexList {
	typedef typename Append<typename ConstructIndexList<N - 1>::Result, N - 1>::Result Result;
};
template <> struct ConstructIndexList<0> {
	typedef IndexList<> Result;
};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
const char XORKEY = static_cast<char>(RandomNumber(0, 0xFF));
__forceinline constexpr char EncryptCharacter(const char Character, int Index) {
	return Character ^ (XORKEY + Index);
}
template <typename IndexList> class CXorString;
template <int... Index> class CXorString<IndexList<Index...> > {
private:
	char Value[sizeof...(Index)+1];
public:
	__forceinline constexpr CXorString(const char* const String)
		: Value{ EncryptCharacter(String[Index], Index)... } {}

	__forceinline char* decrypt() {
		for (int t = 0; t < sizeof...(Index); t++) {
			Value[t] = Value[t] ^ (XORKEY + t);
		}
		Value[sizeof...(Index)] = '\0';
		return Value;
	}

	__forceinline char* get() {
		return Value;
	}
};

const wchar_t XORKEYW = static_cast<wchar_t>(RandomNumber(0, 0xFFFF));
__forceinline constexpr wchar_t EncryptCharacterW(const wchar_t Character, int Index) {
	return Character ^ (XORKEYW + Index);
}
template <typename IndexList> class CXorStringW;
template <int... Index> class CXorStringW<IndexList<Index...> > {
private:
	wchar_t Value[sizeof...(Index)+1];
public:
	__forceinline constexpr CXorStringW(const wchar_t* const String)
		: Value{ EncryptCharacterW(String[Index], Index)... } {}

	__forceinline wchar_t* decrypt() {
		for (int t = 0; t < sizeof...(Index); t++) {
			Value[t] = Value[t] ^ (XORKEYW + t);
		}
		Value[sizeof...(Index)] = '\0';
		return Value;
	}

	__forceinline wchar_t* get() {
		return Value;
	}
};

#define XorS(X, String) CXorString<ConstructIndexList<sizeof(String)-1>::Result> X(String)
#define XorString( String ) ( CXorString<ConstructIndexList<sizeof( String ) - 1>::Result>( String ).decrypt() )
#define XorSW(X, String) CXorStringW<ConstructIndexList<sizeof(String)-1>::Result> X(String)
#define XorStringW( String ) ( CXorStringW<ConstructIndexList<sizeof( String ) - 1>::Result>( String ).decrypt() )
////////////////////////////////////////////////////////////////////






#include <winnt.h>
#include <winternl.h>

constexpr uint32_t val_32_const = 0x811c9dc5;
constexpr uint32_t prime_32_const = 0x1000193;
constexpr uint64_t val_64_const = 0xcbf29ce484222325;
constexpr uint64_t prime_64_const = 0x100000001b3;

inline constexpr uint32_t hash_32_fnv1a_const(const char* const str, const uint32_t value = val_32_const) noexcept {
	return (str[0] == '\0') ? value : hash_32_fnv1a_const(&str[1], (value ^ uint32_t(str[0])) * prime_32_const);
}

inline constexpr uint64_t hash_64_fnv1a_const(const char* const str, const uint64_t value = val_64_const) noexcept {
	return (str[0] == '\0') ? value : hash_64_fnv1a_const(&str[1], (value ^ uint64_t(str[0])) * prime_64_const);
}


constexpr uint32_t cx_fnv_hash(const char* str) {
	return hash_32_fnv1a_const(str);
}

// Thread Environment Block (TEB)
#if defined(_M_X64) // x64
static PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
static PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif
// Process Environment Block (PEB)

static void* GetModuleProcAddressByHash(void* moduleBase, uint32_t procNameHash) {

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
	PIMAGE_NT_HEADERS headers32 = (PIMAGE_NT_HEADERS)((char*)moduleBase + dosHeader->e_lfanew);
	if (headers32->Signature != IMAGE_NT_SIGNATURE) return NULL;
	if (headers32->FileHeader.SizeOfOptionalHeader < 96 || headers32->OptionalHeader.NumberOfRvaAndSizes == 0) return NULL;
	DWORD EdtOffset = headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!EdtOffset) return NULL;

	typedef struct _EXPORT_DIRECTORY_TABLE {
		DWORD ExportFlags;
		DWORD TimeStamp;
		WORD MajorVersion;
		WORD MinorVersion;
		DWORD NameRVA;
		DWORD OrdinalBase;
		DWORD ExportAddressTableSize;
		DWORD NamePointerTableSize;
		DWORD ExportAddressTableRVA;
		DWORD NamePointerTableRVA;
		DWORD OrdinalTableRVA;
	} EXPORT_DIRECTORY_TABLE, *PEXPORT_DIRECTORY_TABLE;

	PEXPORT_DIRECTORY_TABLE EdtPtr =
		(PEXPORT_DIRECTORY_TABLE)((char*)moduleBase + EdtOffset);
	PVOID OrdinalTable = (PBYTE)moduleBase + EdtPtr->OrdinalTableRVA;
	PVOID NamePointerTable = (PBYTE)moduleBase + EdtPtr->NamePointerTableRVA;
	PVOID ExportAddressTable = (PBYTE)moduleBase + EdtPtr->ExportAddressTableRVA;

	for (DWORD i = 0; i < EdtPtr->NamePointerTableSize; i++) {
		DWORD NameRVA = ((PDWORD)NamePointerTable)[i];
		const char* NameAddr = (char*)moduleBase + NameRVA;

		//if (strcmp(NameAddr, procName))
		//	continue;
		if (cx_fnv_hash(NameAddr) != procNameHash)
			continue;


		WORD Ordinal = ((PWORD)OrdinalTable)[i] + (WORD)EdtPtr->OrdinalBase;
		WORD RealOrdinal = Ordinal - (WORD)EdtPtr->OrdinalBase;
		DWORD ExportAddress = 0;
		ExportAddress = ((PDWORD)ExportAddressTable)[RealOrdinal];
		void* FinalAddr = (char*)moduleBase + ExportAddress;
		return FinalAddr;
	}
	return NULL;
}
static void* GetProcPtr(uint32_t procNameHash, const wchar_t* dllName = NULL, const char* name = NULL) {
	//Get Pointer to PEB structure
	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	//Reference point / tail to compare against, since the list is circular
	PLIST_ENTRY moduleListTail = &pebPtr->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY moduleList = moduleListTail->Flink;
	//Traverse the list until moduleList gets back to moduleListTail
	do {
		char* modulePtrWithOffset = (char*)moduleList;
		//List is intrusive, a part of a larger LDR_DATA_TABLE structure,
		//so cast the pointer
		PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)modulePtrWithOffset;
		//Compare the name of the entry against our parameter name
		//Note that the name is a wide string

		void *funcPtr = nullptr;
		//The actual position of the image base address inside
		//the LDR_DATA_TABLE_ENTRY seems to change *a lot*.
		//Apparently on Windows 8.1 it wasn't located in the
		//correct place according to my structures defined above.
		//It should have been "DllBase", but apparently it
		//was 8 bytes back, inside Reserved2[0]
		void* DllBase = module->Reserved2[0];

		if (!dllName || _wcsicmp(module->FullDllName.Buffer, dllName) == 0)
			if (funcPtr = GetModuleProcAddressByHash(DllBase, procNameHash)) {

#if defined(_DEBUG) || defined(_MY_DEBUG)
				if (name && strcmp(name, "DefWindowProcW1222_test") == 0) {

					wchar_t errMsg[1024] = { 0 };
					swprintf_s(errMsg, L"Module: %s\n%u\n", module->FullDllName.Buffer, (int)funcPtr);
					(MessageBoxW)(0, errMsg, (L"Find function HeapAlloc"), MB_OK);
				}
				else
#endif
					return funcPtr;
			}
		moduleList = moduleList->Flink;
	} while (moduleList != moduleListTail);
#if defined(_DEBUG) || defined(_MY_DEBUG)
	char errMsg[1024] = { 0 };
	sprintf_s(errMsg, "Function: %s\nHash: %u", name ? name : "NULL", procNameHash);
	(MessageBoxA)(0, errMsg, ("Can't find function"), MB_ICONERROR | MB_OK);
	ExitProcess(0);
#endif
	return NULL;
}




static void *get_func_by_hash(uint32_t hash, const wchar_t* dllName = NULL, const char* name = NULL) {
	return GetProcPtr(hash, dllName, name);
}
template <uint32_t hash>
static void* lazyimport_get(const wchar_t* dllName = NULL, const char* name = NULL)
{
	static void* pfn;
	if (!pfn)
		pfn = get_func_by_hash(hash, dllName, name);
	return pfn;
}

#if defined(_DEBUG) || defined(_MY_DEBUG)
#define IFN_DLL(dllName,name) (reinterpret_cast<decltype(&name)>(lazyimport_get<cx_fnv_hash(#name)>(dllName,#name)))
#define IFN(name) (reinterpret_cast<decltype(&name)>(lazyimport_get<cx_fnv_hash(#name)>(0,#name)))
#define IFN_PTR_DLL(dllName,name) (lazyimport_get<cx_fnv_hash(#name)>(dllName,#name))
#define IFN_PTR(name) (lazyimport_get<cx_fnv_hash(#name)>(0,#name))
#else
#define IFN_DLL(dllName,name) (reinterpret_cast<decltype(&name)>(lazyimport_get<cx_fnv_hash(#name)>(dllName)))
#define IFN(name) (reinterpret_cast<decltype(&name)>(lazyimport_get<cx_fnv_hash(#name)>()))
#define IFN_PTR_DLL(dllName,name) (lazyimport_get<cx_fnv_hash(#name)>(dllName))
#define IFN_PTR(name) (lazyimport_get<cx_fnv_hash(#name)>())
#endif // DEBUG


#endif