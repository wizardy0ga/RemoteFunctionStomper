```
 _____             _   _            _____ _
|   __|_ _ ___ ___| |_|_|___ ___   |   __| |_ ___ _____ ___ ___ ___
|   __| | |   |  _|  _| | . |   |  |__   |  _| . |     | . | -_|  _|
|__|  |___|_|_|___|_| |_|___|_|_|  |_____|_| |___|_|_|_|  _|___|_|
By wizardy0ga                                          |_|   v1.1.0
Github: https://github.com/wizardy0ga/RemoteFunctionStomper
```

<div align="center">
    <img src="/img/demo.png">
</div>

### Notice
I did not discover this technique. This is a known code execution technique.

### About

This is a small C program that allows the operator to inject a payload into a remote process via function stomping. The program will read the payload from a .bin file and target the remote process, DLL and exported function that is specified by the operator.

### What is Function Stomping?

Function stomping is the act of overwriting the code that is executed by an exported DLL function. When the function is called, the code that was written to the function will be executed instead of the original function code. This will make the thread of execution appear to have executed a benign function.

Since DLLs will share the same function addresses among processes, it is possible to locate the function address inside of our own process and overwrite the function in a remote process with a malicious payload.  
  
> [!IMPORTANT]
> The DLL containing the targeted function must already be loaded into the target process for the function stomping method to work.

### Under The Hood

<div align="center">
    <img src="/img/notepad_user32.png">  

In the [example photo](/img/demo.png), the program found [MessageBoxW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw) at the memory address 0x7FFCFD9DB290 which falls within the available memory ranges of the User32.dll in the notepad.exe process. Specifically, the function is located in the memory image with a base address of 0x7FFCFD961000 at an offset of 0x7A290 bytes.  
</div>
  
  
<div align="center">
    <img src="/img/normal_function.png">

This is the normal function code for MessageBoxW at 0x7FFCFD9DB290 in User32.dll. The function code is offset by 0x7A290 bytes from 0x7FFCFD961000.
</div>

<div align="center">
    <img src="/img/messageboxw_overwrite.png">  

By writing to 0x7FFCFD9DB290 in the notepad.exe process, we can change the code that is executed when the function is called. In this example, the function is overwritten with a windows/x64/shell_reverse_tcp payload from metasploit. Since we know the payload is 460  bytes (0x1CC), we can locate the payload between the offsets 0x7A290 and 0x7A45C.
  
</div>
<div align="center">
    <img src="/img/notepad_threads.png">  

After the thread is created, we can see that it's entry point is User32.dll!MessageBoxW. This makes the thread appear to be executing the specified function instead of our payload.  
  
</div>
  
### Usage

```
FunctionStomper.exe <path to payload.bin> <target process name> <dll name> <function name>
```

### Created With

#### Visual Studio 2022

### References

[From Process Injection to Function Hijacking](https://klezvirus.github.io/RedTeaming/AV_Evasion/FromInjectionToHijacking/#:~:text=Function%20stomping%20is%20a%20technique,overwrites%20a%20specific%20exported%20function.)

[Function Stomping](https://github.com/Idov31/FunctionStomping)

### Change Log

#### Version 1.1.0

- Added check operation to ensure specified DLL exists in the target process before injecting payload.
- Added ability to use any letter casing in the target process argument.
- Added error checking for insufficient privileges when accessing a process running at a higher privilege / integrity level.