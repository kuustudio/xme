#include <iostream>
#include <conio.h>

#include "xme.h"

static void Usage(const wchar_t* path)
  {
  wchar_t name[_MAX_FNAME];
  _wsplitpath_s(path, nullptr, 0, nullptr, 0, name, sizeof(name), nullptr, 0);
  std::cout << std::endl << "USAGE : " << std::endl << std::endl;
  std::wcout << L"    " << name << L"   DllFileName" << std::endl;
  std::cout  << std::endl;
  }

int wmain(int argc, const wchar_t* argv[])
  {
  if(argc != 2)
    {
    Usage(argv[0]);
    return 0;
    }
  std::cout << std::endl;

  const auto res = LrdDll(argv[1]);
  if(!XOK(res))
    {
    std::cout << "Fail : " << XME_Error(res) << "  " << XME_ErrorEx(res) << std::endl;
    std::cout << "Press any key to exit." << std::endl;
    _getch();
    return 1;
    }
  LPVOID pe = (LPVOID)res;
  std::cout << "Load : " << (void*)pe << std::endl;

  //std::cout << (void*)GetProcAddress((HMODULE)pe, "TestExport") << std::endl;
  std::cout << (void*)DllProcAddr(pe, "TestExport") << std::endl;

  std::cout << "Press any key to free dll..." << std::endl;
  _getch();
  const auto unres = UnLrdDll(pe);
  if(XOK(unres))
    {
    std::cout << "Done." << std::endl;
    }
  else
    {
    std::cout << "Unload Fail." << std::endl;
    }
  _getch();
  return 0;
  }