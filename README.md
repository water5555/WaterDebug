### WaterDebug

**WaterDebug** is an IDA Pro plugin designed to streamline the process of debugging `.so` files and generating Frida hook scripts. It simplifies tasks like expression-based jumping during debugging and automates the creation of Frida hook scripts from IDA function prototypes, making reverse engineering more efficient.

## Features

- **Expression-based Jumping**:  
  Jump to addresses based on expressions like `[[x0] + 0x20]` during debugging, making it easier to follow complex memory patterns.
  
- **Frida Hook Script Generation**:  
  Automatically generates Frida hook scripts based on IDA's function prototypes, allowing you to quickly instrument functions with Frida hooks.

- **Seamless Debugging**:  
  Enhanced support for debugging `.so` files, making it easier to analyze Android native libraries or other shared objects in IDA Pro.

- **User-friendly**:  
  A simple yet powerful tool for reverse engineers, reducing the time needed to write and test Frida hooks manually.

## Installation (Windows Only)

### Prerequisites

- **Operating System**: Windows (This plugin is designed for Windows and does not support other platforms like macOS or Linux).
- **Python version**: WaterDebug requires **Python 3.10 or higher**. Please ensure you are using a compatible Python version before proceeding.
  - You can check your Python version with the following command:
    ```bash
    python --version
    ```

### Steps to Install

1. **Clone the Repository**:  
   Clone the `WaterDebug` repository to your local machine:
   ```bash
   git clone https://github.com/water5555/WaterDebug.git
   
2. **Install Required Python Dependencies**:
   With your Python environment activated, install the required dependencies using `pip`:

   ```bash
   python -m pip install lark
   python -m pip install pyperclip
   ```

3. **Place the Plugin in the IDA Plugin Directory**:
   After installing the dependencies, place the plugin files into the appropriate plugin directory for IDA Pro (usually under `plugins` or `IDAPro/plugins`).

## Usage

### Automatic Jumping with Hotkey (W)

During debugging, you can use expressions like `[[x0] + 0x20]` to jump to specific memory addresses directly. This feature allows you to trace dynamic memory accesses more easily, especially when dealing with complex memory structures.

#### Example:

If `x0` contains the base address of a structure, you can jump to an offset within that structure with the following expression:

```bash
[[x0] + 0x20]
```

Press the **W** key during debugging to automatically jump to the next relevant address based on the expression. This will speed up your analysis by quickly navigating through memory addresses.

### Automatic Frida Hook Script Generation with Hotkey (Ctrl + Shift + F)

While working with `.so` files in IDA, you can use the **Ctrl + Shift + F** hotkey to automatically generate Frida hook scripts for the selected function. The plugin will generate a Frida hook script based on the IDA function prototype, including arguments and return values. This feature speeds up the process of hooking functions, allowing you to focus on more complex tasks rather than manually writing scripts.

#### Example:

After selecting a function in IDA, press `Ctrl + Shift + F` to automatically generate the Frida hook script for that function. The generated script might look like this:

```javascript
var module_name = 'libkernel.so';
var offset = 22239992;
var base_address = Process.findModuleByName(module_name);
if (base_address !== null) {
    var target_address = base_address.base.add(offset);
    console.log('Hooking function: Java_com_tencent_qqnt_kernel_nativeinterface_IKernelMsgService_00024CppProxy_native_1getRichMediaFilePathForMobileQQSend at address: ' + target_address);

    Interceptor.attach(target_address, {
        onEnter: function(args) {
            console.log('Function Java_com_tencent_qqnt_kernel_nativeinterface_IKernelMsgService_00024CppProxy_native_1getRichMediaFilePathForMobileQQSend entered');
            console.log('Register X0: ' + this.context.x0);  // env (register: X0)
            console.log('Register X1: ' + this.context.x1);  // thiz (register: X1)
            console.log('Register X2: ' + this.context.x2);  // nativeRef (register: X2)
            console.log('Register X3: ' + this.context.x3);  // richMediaFilePathInfo (register: X3)

            // 打印函数参数：
            console.log('env: ' + args[0]);  // env (JNIEnv *)
            console.log('thiz: ' + args[1]);  // thiz (jobject)
            console.log('nativeRef: ' + args[2]);  // nativeRef (jlong)
            console.log('richMediaFilePathInfo: ' + args[3]);  // richMediaFilePathInfo (jobject)
        },
        onLeave: function(retval) {
            console.log('Return Register X0: ' + this.context.x0);  // X0 (register)
            console.log('Return value: ' + retval);  // jstring (return type)
        }
    });
} else {
    console.log('Module not found');
}
```
### Runtime Module Dump with Hotkey (Alt + D)

WaterDebug supports dumping the **runtime memory image of a loaded module** during debugging.

This feature allows you to export the module exactly as it exists in memory at runtime, which is useful when analyzing modules that have been decrypted, patched, or modified dynamically.

Press **Alt + D** during debugging to dump the current runtime module to a file.

#### Dump Output Path Configuration

The dump output path is defined inside the following function:

```python
dump_runtime_module_segments()
````

If you need to change where the dumped module is saved, modify the output path inside
`WaterDebug.py` in the `dump_runtime_module_segments` function.

Example:

```python
out_path = r"C:\Users\water\Desktop\dump_" + os.path.basename(info.name)
```

You can adjust this path according to your workflow (for example, saving the dump relative to the current IDB file or to a custom directory).
