# hooking-engine

Hooking engine for x86/x64, supports inline hooking, IAT hooking and various dll injection techniques.  
## Subprojects
### HookingLib  
Includes 2 kinds of hooks that redirect a given function to a new one:
- InlineHook - overwrites the first few bytes of the given function in memory with a relative jump instruction to a "bridge" (within 2GB from the hooked function).  
The bridge contains the overwritten instructions and another relative jump the new function (in x86)    
or an absolute jump (in x64, because a relative jump might not reach it).  
Uses the [distorm](https://github.com/gdabah/distorm) library to disassemble the first instruction of the function (so it won't cut instructions while copying them to the bridge).
- IATHook - overwrites the function pointer in the IAT table.

### InjectionLib
Includes several dll injectors:
- LoadLibraryInjector - classic LoadLibrary & CreateRemoteThread dll injector.
- WindowsHookInjector - injects using the function SetWindowsHookEx.
- ManualFileInjector - performs manual mapping of a given PE file to the target process.
- ManualResourceInjector - performs manual mapping of a given PE resource to the target process.

### InterprocessCommunication
Currently contains a SharedMemory class that creates and manages file mapping between the injected dll and the injector (in different processes).  
Very useful for debugging.

### Injector
Console application to easily use the different dll injectors.  
```
Usage: Injector (injector_type) (dll_path) (PID/process_name)

Injector types:
-ll      Load library injector.
-wh      Windows hook injector.
-mf      Manual mapping file injector.
```
