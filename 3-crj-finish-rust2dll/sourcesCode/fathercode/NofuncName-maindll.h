#ifdef BUILD_DLL
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif
/*这下面写的是导出的函数*/
EXPORT void DllMainEntry();