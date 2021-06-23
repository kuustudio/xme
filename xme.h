#ifndef _XME_H_
#define _XME_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static_assert(sizeof(size_t) == sizeof(void*));

enum XME_ERROR_ENUM
  {
  XME_OK,
  XME_CreateFile,
  XME_GetFileSizeEx,
  XME_Large,
  XME_LocalAlloc,
  XME_LocalLock,
  XME_ReadFile,
  XME_Lock,
  XME_VirtualAlloc,
  XME_MappingDll,
  XME_Relocation,
  XME_ImportDLL,
  XME_ImportTable,
  XME_SetImageBase,
  XME_ExecuteTLS,
  XME_ExecDllMain,
  XME_UnLoad,
  XME_DllProcAddr,
  };

typedef unsigned long long XME_Result;

static_assert(8 == sizeof(XME_Result));
static_assert(4 == sizeof(XME_ERROR_ENUM));
static_assert(4 == sizeof(DWORD));


XME_ERROR_ENUM XME_Error(const XME_Result res);
DWORD XME_ErrorEx(const XME_Result res);
bool XOK(const XME_Result res);

XME_Result LrdDll(LPCTSTR lpFileName);
XME_Result UnLrdDll(LPVOID PE);
XME_Result DllProcAddr(LPVOID PE, LPCSTR lpProcName);

#endif  //_XME_H_