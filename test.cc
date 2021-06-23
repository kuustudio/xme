#include <iostream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

class xx
  {
  public:
    xx()
      {
      std::cout << "==== Test xx init." << std::endl;
      OutputDebugStringA("==== Test xx init.");
      }
    ~xx()
      {
      std::cout << "==== Test xx free." << std::endl;
      OutputDebugStringA("==== Test xx free.");
      }
  };

static const xx b;

extern "C" __declspec(dllexport) void TestExport()
  {
  std::cout << (void*)&b << std::endl;
  }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
  {
  UNREFERENCED_PARAMETER(hModule);
  UNREFERENCED_PARAMETER(lpReserved);
  switch(ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
      std::cout << "==== Test load." << std::endl;
      OutputDebugStringA("==== Test load.");
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      std::cout << "==== Test free." << std::endl;
      OutputDebugStringA("==== Test free.");
      break;
    }
  return TRUE;
  }