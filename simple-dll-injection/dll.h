#if !defined INJ_DLL_H
#define INJ_DLL_H

#ifdef INJ_DLL_EXPORTS
#define INJAPI __declspec(dllexport)
#else
#define INJAPI __declspec(dllimport)
#endif

#endif // !defined(INJ_DLL_H)