#include "xme.h"

////////////////////////////////////////////////////////////////
XME_ERROR_ENUM XME_Error(const XME_Result res)
  {
  return (XME_ERROR_ENUM)((res >> 32) & 0x7FFFFFFF);
  }

DWORD XME_ErrorEx(const XME_Result res)
  {
  return (DWORD)(res & 0xFFFFFFFF);
  }

static XME_Result XERROR(const XME_ERROR_ENUM ec, const DWORD le = GetLastError())
  {
  XME_Result res = ec | 0x80000000;
  res <<= 32;
  return res | le;
  }

template<typename T>
XME_Result XRETURN(const T v)
  {
  return (XME_Result)v;
  }

bool XOK(const XME_Result res)
  {
  return 0 == (res & 0x8000000000000000);
  }
////////////////////////////////////////////////////////////////
static XME_Result LoadFile(LPCTSTR lpFileName)
  {
  // 打开文件。
  HANDLE hFile = CreateFileW(
    lpFileName,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_READONLY,
    NULL);
  if(INVALID_HANDLE_VALUE == hFile)
    {
    return XERROR(XME_CreateFile);
    }
  // 查询大小。
  LARGE_INTEGER FileSize;
  if(FALSE == GetFileSizeEx(hFile, &FileSize))
    {
    const XME_Result res = XERROR(XME_GetFileSizeEx);
    CloseHandle(hFile);
    return res;
    }
  if(0 != FileSize.HighPart)
    {
    const XME_Result res = XERROR(XME_Large);
    CloseHandle(hFile);
    return res;
    }
  // 申请内存。
  DWORD uBytes = FileSize.LowPart;
  HLOCAL hMem = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
  if(NULL == hMem)
    {
    const XME_Result res = XERROR(XME_LocalAlloc);
    CloseHandle(hFile);
    return res;
    }
  // 锁定内存。
  LPVOID lpBuffer = LocalLock(hMem);
  if(NULL == lpBuffer)
    {
    const XME_Result res = XERROR(XME_LocalLock);
    CloseHandle(hFile);
    LocalFree(hMem);
    return res;
    }
  // 读取文件。
  DWORD NumberOfBytesRead = 0;
  if(FALSE == ReadFile(hFile, lpBuffer, uBytes, &NumberOfBytesRead, NULL))
    {
    const XME_Result res = XERROR(XME_ReadFile);
    CloseHandle(hFile);
    LocalUnlock(lpBuffer);
    LocalFree(hMem);
    return res;
    }
  // 释放文件句柄，解锁内存，但不释放，返回内存句柄。
  CloseHandle(hFile);
  LocalUnlock(lpBuffer);
  return XRETURN(hMem);
  }
////////////////////////////////////////////////////////////////
static bool MappingDll(LPVOID PE, const IMAGE_DOS_HEADER& DosHeader)
  {
  try
    {
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    // 所有 头 + 节表 头大小。
    const DWORD SizeOfHeaders = NtHeaders.OptionalHeader.SizeOfHeaders;
    // 写入所有 头 + 节表 头。
    CopyMemory(PE, &DosHeader, SizeOfHeaders);
    // 节表数量。
    const size_t NumberOfSections = NtHeaders.FileHeader.NumberOfSections;
    // 获取第一个 节表头 的地址。
    IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)((size_t)&NtHeaders + sizeof(NtHeaders));
    // 写入所有 节表。
    for(size_t i = 0; i < NumberOfSections; ++i)
      {
      if((0 == pSectionHeader->VirtualAddress) || (0 == pSectionHeader->SizeOfRawData))
          {
          ++pSectionHeader;
          continue;
          }
      void* src = (void*)((size_t)&DosHeader + pSectionHeader->PointerToRawData);
      void* dst = (void*)((size_t)PE + pSectionHeader->VirtualAddress);
      CopyMemory(dst, src, pSectionHeader->SizeOfRawData);
      ++pSectionHeader;
      }
    return true;
    }
  catch(...)
    {
    return false;
    }
  }
////////////////////////////////////////////////////////////////
/*
  重定位表的结构：
    DWORD sectionAddress
    DWORD size  // 包括本节需要重定位的数据

  例如 1000 节 需要修正 5 个重定位数据的话，重定位表的数据是
  00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
  -----------   -----------      ----
  给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节

  重定位表是若干个相连，如果 address 和 size 都是 0 ， 表示结束。
  需要修正的地址是 12 位的，高 4 位是形态字，intel cpu下是 3 。
  
	假设 Base 是 0x600000 ，而文件中设置的缺省 ImageBase 是 0x400000 ，则修正偏移量就是 0x200000 。
	注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址。
*/
static bool Relocation(const IMAGE_DOS_HEADER& DosHeader)
  {
  try
    {
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    // 是否有重定位表。
    if((void*)pLoc == (void*)&DosHeader) return true;
    // 计算修正值。
    const size_t Delta = (size_t)&DosHeader - NtHeaders.OptionalHeader.ImageBase;
    // 扫描重定位表。
    while(0 != (pLoc->VirtualAddress + pLoc->SizeOfBlock))
      {
      const WORD* pLocData = (const WORD*)((size_t)pLoc + sizeof(IMAGE_BASE_RELOCATION));
      // 计算本节需要修正的重定位项（地址）的数目。
      size_t nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      for(size_t i = 0; i < nNumberOfReloc; ++i)
        {
        // 每个 WORD 由两部分组成。高 4 位指出了重定位的类型，WINNT.H 中的一系列 IMAGE_REL_BASED_xxx 定义了重定位类型的取值。
        // 低 12 位是相对于 VirtualAddress 域的偏移，指出了必须进行重定位的位置。
  #ifdef _WIN64
        const WORD Flag = 0xA000;
        // 对于 IA-64 的可执行文件，重定位似乎总是 IMAGE_REL_BASED_DIR64 类型的。
  #else
        const WORD Flag = 0x3000;
        // 对于 x86 的可执行文件，所有的基址重定位都是 IMAGE_REL_BASED_HIGHLOW 类型的。
  #endif
        if(Flag != (pLocData[i] & 0xF000)) continue;
        // 需要修正。
        size_t& Address = *(size_t*)((size_t)&DosHeader + pLoc->VirtualAddress + (pLocData[i] & 0xFFF));
        Address += Delta;
        }
      pLoc = (PIMAGE_BASE_RELOCATION)((size_t)pLoc + pLoc->SizeOfBlock);
      }
    return true;
    }
  catch(...)
    {
    return false;
    }
  }
////////////////////////////////////////////////////////////////
static XME_Result ImportTable(const IMAGE_DOS_HEADER& DosHeader)
  {
  try
    {
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for(; 0 != pImportTable->OriginalFirstThunk; ++pImportTable)
      {
      // 获取导入表中 DLL 名称并加载。
      LPCSTR pDllName = (LPCSTR)((size_t)&DosHeader + pImportTable->Name);
      HMODULE hDll = LoadLibraryA(pDllName);
      if(NULL == hDll)
        {
        return XERROR(XME_ImportDLL);
        }

      // 获取 OriginalFirstThunk 以及对应的导入函数名称表首地址。
      PIMAGE_THUNK_DATA lpImportNameArray = (PIMAGE_THUNK_DATA)((size_t)&DosHeader + pImportTable->OriginalFirstThunk);
      // 获取 FirstThunk 以及对应的导入函数地址表首地址。
      PIMAGE_THUNK_DATA lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((size_t)&DosHeader + pImportTable->FirstThunk);
      for(size_t i = 0; 0 != lpImportNameArray[i].u1.AddressOfData; ++i)
        {
        // 获取IMAGE_IMPORT_BY_NAME结构
        PIMAGE_IMPORT_BY_NAME lpImportByName = (PIMAGE_IMPORT_BY_NAME)((size_t)&DosHeader + lpImportNameArray[i].u1.AddressOfData);
        // 判断导出函数是序号导出还是函数名称导出。
        // 当 IMAGE_THUNK_DATA 值的最高位为 1 时，表示函数以序号方式输入，这时，低位被看做是一个函数序号。
        const size_t Flag = (size_t)0x1 << (sizeof(size_t) * 8 - 1);
        const size_t FuncAddr = (size_t)GetProcAddress(hDll,
          (Flag & lpImportNameArray[i].u1.Ordinal) ?
            (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF) :
            (LPCSTR)lpImportByName->Name);
        // 注意此处的函数地址表的赋值，要对照PE格式进行装载。
        lpImportFuncAddrArray[i].u1.Function = FuncAddr;
        }
      }
    return XRETURN(XME_OK);
    }
  catch(...)
    {
    return XERROR(XME_ImportTable);
    }
  }
////////////////////////////////////////////////////////////////
static bool SetImageBase(const IMAGE_DOS_HEADER& DosHeader)
  {
  try
    {
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    const size_t offset = (size_t)&(NtHeaders.OptionalHeader.ImageBase) - (size_t)&DosHeader;
    void* pImageBase = (void*)((size_t)&DosHeader + offset);
    void* ImageBase = (void*)&DosHeader;
    CopyMemory(pImageBase, &ImageBase, sizeof(ImageBase));
    // 额外把 MZ 和 PE 破坏
    *(void**)&DosHeader = nullptr;
    *(void**)&NtHeaders = nullptr;
    return true;
    }
  catch(...)
    {
    return false;
    }
  }
////////////////////////////////////////////////////////////////
static bool ExecuteTLS(const IMAGE_DOS_HEADER& DosHeader, DWORD dwReason)
  {
  try
    {
    //if(nullptr != &DosHeader) return true;// 其实 TLS 的处理没有意义。
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    IMAGE_DATA_DIRECTORY& TLSDirectory = *(IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(0 == TLSDirectory.VirtualAddress)  return true;
    IMAGE_TLS_DIRECTORY& tls = *(IMAGE_TLS_DIRECTORY*)((size_t)&DosHeader + TLSDirectory.VirtualAddress);
    PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls.AddressOfCallBacks;
    if(nullptr == callback) return true;
    for(; *callback; ++callback)
      {
      (*callback)((LPVOID)&DosHeader, dwReason, NULL);
      }
    return true;
    }
  catch(...)
    {
    return false;
    }
  }

////////////////////////////////////////////////////////////////
static bool ExecDllMain(const IMAGE_DOS_HEADER& DosHeader, DWORD dwReason)
  {
  try
    {
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    using DllMainFunction = BOOL(WINAPI*)(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved);
    DllMainFunction DllMain = (DllMainFunction)((size_t)&DosHeader + NtHeaders.OptionalHeader.AddressOfEntryPoint);
    DllMain((HINSTANCE)&DosHeader, dwReason, nullptr);
    return true;
    }
  catch(...)
    {
    return false;
    }
  }
////////////////////////////////////////////////////////////////
static bool UnLrdImport(const IMAGE_DOS_HEADER& DosHeader)
  {
  try
    {
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for(; 0 != pImportTable->OriginalFirstThunk; ++pImportTable)
      {
      // 获取导入表中 DLL 名称并加载。
      LPCSTR pDllName = (LPCSTR)((size_t)&DosHeader + pImportTable->Name);
      HMODULE hLibModule = GetModuleHandleA(pDllName);
      if(NULL != hLibModule)
        {
        FreeLibrary(hLibModule);
        }
      }
    return true;
    }
  catch(...)
    {
    return false;
    }
  }
////////////////////////////////////////////////////////////////
XME_Result LrdDll(LPCTSTR lpFileName)
  {
  LPVOID PE = nullptr;
  // 设置作用域，是因为 DLL 文件缓存不需要只需要在 Mapping 时存在，Mapping 后可以释放。
  // 不把 缓存读取整合进 Mapping ，是有异常抛出考虑，避免资源泄露不释放。
  {
  // 读取 DLL 至内存。
  const XME_Result res = LoadFile(lpFileName);
  if(!XOK(res)) return res;
  HLOCAL hMem = (HLOCAL)res;
  // 锁定内存。
  LPVOID lpBuffer = LocalLock(hMem);
  if(NULL == lpBuffer)
    {
    const XME_Result r = XERROR(XME_Lock);
    LocalFree(hMem);
    return r;
    }
  // 获取镜像大小。
  const IMAGE_DOS_HEADER& DosHeader = *(IMAGE_DOS_HEADER*)lpBuffer;
  const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  const DWORD SizeOfImage = NtHeaders.OptionalHeader.SizeOfImage;
  // 开辟空间。
  PE = VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if(NULL == PE)
    {
    const XME_Result r = XERROR(XME_VirtualAlloc);
    LocalUnlock(lpBuffer);
    LocalFree(hMem);
    return r;
    }
  // 平铺。
  if(!MappingDll(PE, DosHeader))
    {
    LocalUnlock(lpBuffer);
    LocalFree(hMem);
    VirtualFree(PE, 0, MEM_RELEASE);
    return XERROR(XME_MappingDll);
    }
  LocalUnlock(lpBuffer);
  LocalFree(hMem);
  }
  const IMAGE_DOS_HEADER& DosHeader = *(IMAGE_DOS_HEADER*)PE;
  // 重定位。注意：重定位之前不能填写加载基址。
  if(!Relocation(DosHeader))
    {
    VirtualFree(PE, 0, MEM_RELEASE);
    return XERROR(XME_Relocation);
    }
  // 填写导入表。
  const XME_Result res = ImportTable(DosHeader);
  if(!XOK(res))
    {
    VirtualFree(PE, 0, MEM_RELEASE);
    return res;
    }
  // 填写文件加载基址。
  if(!SetImageBase(DosHeader))
    {
    VirtualFree(PE, 0, MEM_RELEASE);
    return XERROR(XME_SetImageBase);
    }
  // TLS
  if(!ExecuteTLS(DosHeader, DLL_PROCESS_ATTACH))
    {
    VirtualFree(PE, 0, MEM_RELEASE);
    return XERROR(XME_ExecuteTLS);
    }
  // 运行入口函数。
  if(!ExecDllMain(DosHeader, DLL_PROCESS_ATTACH))
    {
    VirtualFree(PE, 0, MEM_RELEASE);
    return XERROR(XME_ExecDllMain);
    }
  
  return XRETURN(PE);
  }

XME_Result UnLrdDll(LPVOID PE)
  {
  const IMAGE_DOS_HEADER& DosHeader = *(IMAGE_DOS_HEADER*)PE;
  const bool tlsok = ExecuteTLS(DosHeader, DLL_PROCESS_DETACH);
  const bool mainok = ExecDllMain(DosHeader, DLL_PROCESS_DETACH);
  const bool uok = UnLrdImport(DosHeader);
  VirtualFree(PE, 0, MEM_RELEASE);
  if(tlsok && mainok) return XRETURN(XME_OK);
  return XERROR(XME_UnLoad);
  }

XME_Result DllProcAddr(LPVOID PE, LPCSTR lpProcName)
  {
  try
    {
    const IMAGE_DOS_HEADER& DosHeader = *(IMAGE_DOS_HEADER*)PE;
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    const IMAGE_DATA_DIRECTORY& ExportEntry = *(const IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    const IMAGE_EXPORT_DIRECTORY& ExportTable = *(const IMAGE_EXPORT_DIRECTORY*)((size_t)&DosHeader + ExportEntry.VirtualAddress);
    const size_t ExportSize = ExportEntry.Size;
    const DWORD* pAddressOfFunction = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfFunctions);
    const DWORD* pAddressOfName = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfNames);
    const DWORD dwBase = ExportTable.Base;
    const WORD* pAddressOfNameOrdinals = (const WORD*)((size_t)&DosHeader + ExportTable.AddressOfNameOrdinals);
    
    LPVOID addr = NULL;

    const DWORD Name = (DWORD)(size_t)lpProcName;
    if(0 == (Name & 0xFFFF0000))
      {
      // 序号查找。
      if(Name < dwBase) return XERROR(XME_DllProcAddr);
      if(Name > dwBase + ExportTable.NumberOfFunctions - 1) return XERROR(XME_DllProcAddr);
      addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[Name - dwBase]);
      }
    else
      {
      for(size_t i = 0; i < (size_t)ExportTable.NumberOfNames; ++i)
        {
        LPCSTR name = (LPCSTR)((size_t)&DosHeader + pAddressOfName[i]);
        if(0 == strcmp(lpProcName, name))
          {
          addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
          break;
          }
        }
      }
    // 判断是否越界。
    if((size_t)addr < (size_t)ExportEntry.VirtualAddress) return XRETURN(addr);
    if((size_t)addr > ((size_t)ExportEntry.VirtualAddress + ExportSize)) return XRETURN(addr);

    CHAR TempDll[MAX_PATH] = {'\0'};
    CHAR TempFunc[MAX_PATH] = {'\0'};
    lstrcpyA(TempDll, (LPCSTR)addr);

    LPSTR p = strchr(TempDll, '.');
    if(NULL == p)
      {
      return XRETURN(addr);
      }
    *p = '\0';
    lstrcpyA(TempFunc, p + 1);
    HMODULE hMod = GetModuleHandleA(TempDll);
    if(NULL == hMod)
      {
      return XERROR(XME_DllProcAddr);
      }
    return XRETURN(GetProcAddress(hMod, TempFunc));
    }
  catch(...)
    {
    return XERROR(XME_DllProcAddr);
    }
  }