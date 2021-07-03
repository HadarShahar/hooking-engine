#include <Windows.h>

// Used to test my manual mapping injectors.
//#define TEST_TLS_CALLBACKS
#ifdef TEST_TLS_CALLBACKS


VOID WINAPI TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(0, L"DLL_PROCESS_ATTACH", L"TLS callback test", MB_ICONINFORMATION);
        break;
    //case DLL_THREAD_ATTACH:
    //    MessageBox(0, L"DLL_THREAD_ATTACH", L"TLS callback test", MB_ICONINFORMATION);
    //    break;
    //case DLL_THREAD_DETACH:
    //    MessageBox(0, L"DLL_THREAD_DETACH", L"TLS callback test", MB_ICONINFORMATION);
    //    break;
    case DLL_PROCESS_DETACH:
        MessageBox(0, L"DLL_PROCESS_DETACH", L"TLS callback test", MB_ICONINFORMATION);
        break;
    }
}

//https://stackoverflow.com/a/36891752
#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma comment (linker, "/INCLUDE:tls_callback_func") 
#else
    #pragma comment (linker, "/INCLUDE:__tls_used") 
    #pragma comment (linker, "/INCLUDE:_tls_callback_func")  
#endif

#ifdef _WIN64
    #pragma const_seg(".CRT$XLF")
    EXTERN_C const
#else
    #pragma data_seg(".CRT$XLF")
    EXTERN_C
#endif
PIMAGE_TLS_CALLBACK tls_callback_func = &TLSCallback;
#ifdef _WIN64
    #pragma const_seg()
#else
    #pragma data_seg()
#endif 


#endif // TEST_TLS_CALLBACKS