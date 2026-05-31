# ReflectiveDLL Injector in Rust

Rust实现的反射DLL注入器，使用NTDLL脱钩来绕过EDR

## 使用

```
Inject ReflectiveDLL.dll into a target process

Usage: injector-rust.exe [OPTIONS] --process <PROCESS>

Options:
  -p, --process <PROCESS>  Target process name (e.g., notepad.exe)
  -u, --url <URL>          URL to download the DLL from (e.g., http://example.com/ReflectiveDLL.dll)
      --rflname <RFLNAME>  ReflectiveLoader function name in ReflectiveDLL.dll [default: yolo]
  -h, --help               Print help
  -V, --version            Print version
```

## 介绍

注入器使用传入的url参数下载反射DLL到内存中，并找到指定的反射函数名称，获得RAW。在目标进程中写入反射dll，并创建反射函数进行反射DLL的自加载。

Rust的编译产物可以很好的防止被逆向分析，并且该注入器使用了NTDLL脱钩技术防止被EDR检测。

[反射DLL参考](https://github.com/ccoskrnl/ReflectiveDLl)

**功能**

- **调试权限**: 尝试注入到高权限进程。

- **文件不落地**: 通过网络下载反射DLL到内存中，避免文件落地。

- **手动解析模块和函数地址**：使用自己实现的`GetModuleHandle`函数，并使用`pelite`解析DLL的内存来查询导出函数的地址，不依赖Windows API的`GetModuleHandle, GetProcAddress`。进一步隐蔽性，避免因为调用API的参数而暴漏恶意行为。

- **间接syscall调用**：动态解析ntdll内存得到所需函数的`ssn`和`syscall ret`指令的地址，构造调用栈欺骗，避免因为syscall的返回地址不在NTDLL模块中从而引起EDR的注意。(无法规避EDR的内核通知回调函数)

- **VEH支持[已实现，暂未使用]**: 修改线程上下文，设置硬件断点，注册自己的向量化异常处理例程，并在异常处理例程中修改线程的上下文。

- **ETW PATCHING**：修改ntdll的`NtTraceEvent`，使其直接返回。减少因为ETW而被发现的概率。（无法避免内核ETW）

## TODO

- [ ] 使用`ZwQuerySystemInformation`探测系统信息。
- [ ] 线程池注入/等待线程劫持
- [ ] APC注入
- [ ] 进程镂空