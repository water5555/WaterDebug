import ida_idd
import pyperclip
from lark import Lark, Transformer, v_args
import os
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import List
import ida_dbg
import ida_idp
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idaapi
import ida_kernwin
import ida_funcs
import ida_bytes

# ============================================================
# 架构信息
# ============================================================

ptr_size = 4

if idaapi.idainfo_is_64bit():
    ptr_size = 8


# ============================================================
# 获取所有寄存器名称列表
# ============================================================
def get_all_registers() -> list:
    return ida_idp.ph_get_regnames()


# ============================================================
# 读取寄存器值
# ============================================================
def read_register(reg_name: str) -> int:
    try:
        return ida_dbg.get_reg_val(reg_name)
    except Exception as e:
        raise RuntimeError(f"读取寄存器失败: {reg_name}")


# ============================================================
# 读取内存值
# ============================================================
def read_memory(addr: int) -> int:
    data = ida_idd.dbg_read_memory(addr, ptr_size)
    if not data:
        raise RuntimeError(f"无法读取内存: 0x{addr:X}")
    return int.from_bytes(data, byteorder="little", signed=False)


# ============================================================
# Lark 表达式文法
# 定义运算优先级
# ============================================================

GRAMMAR = r"""
?start: expr

?expr: expr "+" term   -> add
     | expr "-" term   -> sub
     | term

?term: term "*" factor -> mul
     | term "/" factor -> div
     | factor

?factor: NUMBER
       | REGISTER
       | "[" expr "]"  -> deref
       | "(" expr ")"

NUMBER: /0x[0-9a-fA-F]+|\d+/
REGISTER: /[a-zA-Z_][a-zA-Z0-9_]*/

%ignore " "
"""


# ============================================================
# Transformer
# ============================================================
# EvalTransformer 是 Lark 语法解析树的转换器，用于将解析得到的表达式
# 树转换为实际的数值计算结果。
# 它支持：
#   - 数字常量（十进制或十六进制）
#   - CPU 寄存器读取
#   - 基本算术运算（+、-、*、/）
#   - 内存解引用（类似 [addr] 访问）
#
# 主要方法说明：
#   __init__(reg_list)：
#       初始化时接收寄存器列表，并将其转换为小写集合，方便识别寄存器。
#
#   NUMBER(token)：
#       将表达式中的数字 token 转换为 Python int。
#       支持十进制和十六进制（0x 前缀）。
#
#   REGISTER(token)：
#       将表达式中的寄存器 token 转换为对应的寄存器值。
#       如果寄存器不存在于 reg_list 中，会抛出 RuntimeError。
#
#   add(a, b)、sub(a, b)、mul(a, b)、div(a, b)：
#       对应表达式树的加、减、乘、整除操作。
#
#   deref(value)：
#       实现内存解引用 [value]，即读取给定地址的值。
#       使用 read_memory 函数，根据 ptr_size 从调试器内存中读取数据。

@v_args(inline=True)
class EvalTransformer(Transformer):
    def __init__(self, reg_list):
        self.regs = set(r.lower() for r in reg_list)

    def NUMBER(self, token):
        return int(token.value, 0)

    def REGISTER(self, token):
        name = token.value.lower()
        if name not in self.regs:
            raise RuntimeError(f"未知寄存器: {name}")
        return read_register(name)

    def add(self, a, b): return a + b

    def sub(self, a, b): return a - b

    def mul(self, a, b): return a * b

    def div(self, a, b): return a // b

    def deref(self, value):
        return read_memory(value)


# ============================================================
# 初始化文法解析器
# ============================================================

_parser = Lark(GRAMMAR, parser="lalr")
_reg_list = get_all_registers()


def eval_expression(expr: str) -> int:
    tree = _parser.parse(expr)
    return EvalTransformer(_reg_list).transform(tree)

@dataclass
class ModuleOffsetInfo:
    """
    描述一个地址相对于模块的偏移信息
    """
    mode: str  # "debugger" | "static"
    module: str  # 模块名 / so 名
    base: int  # 模块基址
    offset: int  # 模块内偏移


@dataclass
class ArgDesc:
    """
    描述一个函数参数在「调用约定层面」的完整信息。

    这是一个去 IDA 化、去架构细节但保留 ABI 语义的结构，
    主要用于 Frida / Hook / 动态分析阶段。
    """
    index: int
    # 参数在函数参数列表中的位置（0-based）
    # 与 ABI、IDA funcdata、Frida onEnter(args[index]) 完全一致

    name: str
    # 参数名（来自 IDA）
    # 若 IDA 未命名，可使用 arg{index} 作为回退名

    ida_type: str
    # 参数在 IDA 中的类型字符串快照
    # 例如：JNIEnv * / jobject / jlong
    # 仅用于语义理解与类型映射，不依赖 tinfo_t 对象

    ida_real_type: str
    # IDA实际类型

    mapToFridaType: str
    # 映射到frida类型

    reg: str
    # 参数传递所使用的寄存器名
    # ARM64: x0 / x1 / x2 / x3 ...
    # 若参数通过栈传递，则可为 "stack"


@dataclass
class FuncDesc:
    """
    描述一个函数在「调用约定 + 类型语义 + 所属模块」层面的完整信息。

    这是 Frida Hook 生成、ABI 分析、参数自动映射的核心结构。
    """
    offset: int
    # 函数在 IDA 中的起始地址（EA）

    name: str
    # 函数名（IDA 中的符号名或自动生成名）

    module: str
    # 函数所属模块名，例如 so / dll / image
    # 可以用于动态调试地址映射或生成 Frida 脚本时指明模块

    ret_ida_type: str
    # 返回值的 IDA 类型字符串，例如：jstring / jint / void *

    ret_ida_real_type: str
    # IDA返回值实际类型

    rettypeMapToFridaType: str
    # IDA返回值映射到frida类型

    ret_reg: str
    # 返回值所在的寄存器，ARM64 标量 / 指针返回值通常为 x0

    args: List[ArgDesc]
    # 函数参数描述列表，按参数顺序排列
    # args[index] 对应 ABI 与 Frida 中的第 index 个参数


# 9.1版本类型规划
class BasicType(IntEnum):
    BT_UNK = 0
    BT_VOID = 1
    BTF_VOID = 1  # 保留备用
    BT_INT8 = 2
    BT_INT16 = 3
    BT_INT32 = 4
    BT_INT64 = 5
    BT_INT128 = 6
    BT_INT = 7
    BTF_INT = 7  # 保留备用
    BT_BOOL = 8
    BTF_BOOL = 8  # 保留备用
    BT_FLOAT = 9
    BTF_FLOAT = 9  # 保留备用
    BT_PTR = 10
    BT_ARRAY = 11
    BT_FUNC = 12
    BT_COMPLEX = 13
    BTF_STRUCT = 13  # 保留备用
    BT_BITFIELD = 14
    BT_RESERVED = 15
    BT_UNK_WORD = 16
    BT_UNK_BYTE = 17
    BTF_BYTE = 17  # 保留备用
    BTF_INT8 = 18
    BTF_INT16 = 19
    BTF_INT32 = 20
    BTF_INT64 = 21
    BTF_INT128 = 22
    BTF_SINT = 23
    BTF_DOUBLE = 25
    BTF_UNION = 29
    BT_UNK_QWORD = 32
    BT_UNK_DWORD = 33
    BTF_UCHAR = 34
    BTF_UINT8 = 34
    BTF_UINT16 = 35
    BTF_UINT32 = 36
    BTF_UINT64 = 37
    BTF_UINT128 = 38
    BTF_UINT = 39
    BTF_LDOUBLE = 41
    BTF_ENUM = 45
    BT_UNKNOWN = 48
    BTF_UNK = 48  # 保留备用
    BT_UNK_OWORD = 49
    BTF_CHAR = 50
    BT_SEGREG = 55
    BTF_TBYTE = 57
    BTF_TYPEDEF = 61


FRIDA_TYPES = {
    "void",
    "pointer",
    "int",
    "uint",
    "long",
    "ulong",
    "char",
    "uchar",
    "size_t",
    "ssize_t",
    "float",
    "double",
    "int8",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "int64",
    "uint64",
    "bool"
}

# IDA类型映射Frida类型表
IDA_TYPE_TO_FRIDA_TYPE_MAP = {'BT_UNK': 'pointer', 'BT_VOID': 'void', 'BT_INT8': 'int8', 'BT_INT16': 'int16',
                              'BT_INT32': 'int32',
                              'BT_INT64': 'int64', 'BT_INT128': 'pointer', 'BT_INT': 'int', 'BT_BOOL': 'bool',
                              'BT_FLOAT': 'float',
                              'BT_PTR': 'pointer', 'BT_ARRAY': 'pointer', 'BT_FUNC': 'pointer',
                              'BT_COMPLEX': 'pointer', 'BT_BITFIELD': 'pointer',
                              'BT_RESERVED': 'pointer', 'BT_UNK_WORD': 'pointer', 'BT_UNK_BYTE': 'pointer',
                              'BTF_INT8': 'int8', 'BTF_INT16': 'int16',
                              'BTF_INT32': 'int32', 'BTF_INT64': 'int64', 'BTF_INT128': 'pointer', 'BTF_SINT': 'int',
                              'BTF_DOUBLE': 'double',
                              'BTF_UNION': 'pointer', 'BT_UNK_QWORD': 'pointer', 'BT_UNK_DWORD': 'pointer',
                              'BTF_UCHAR': 'uchar',
                              'BTF_UINT16': 'uint16', 'BTF_UINT32': 'uint32', 'BTF_UINT64': 'uint64',
                              'BTF_UINT128': 'pointer', 'BTF_UINT': 'uint',
                              'BTF_LDOUBLE': 'double', 'BTF_ENUM': 'pointer', 'BT_UNKNOWN': 'pointer',
                              'BT_UNK_OWORD': 'pointer', 'BTF_CHAR': 'char',
                              'BT_SEGREG': 'pointer', 'BTF_TBYTE': 'pointer', 'BTF_TYPEDEF': 'pointer'}



def getRuntimeModuleInfo()-> ida_idd.modinfo_t | None:
    """
    根据当前地址获取其对应的模块信息
    """
    ea = ida_kernwin.get_screen_ea()
    modinfo = idaapi.modinfo_t()
    if ida_dbg.get_module_info(ea, modinfo):
        return modinfo
    else:
        return None

def get_cursor_relative_offset() -> ModuleOffsetInfo:
    """
    根据当前光标地址，计算其相对于“所属模块”的偏移。

    规则说明：
    1. 若调试器已启动：
       - 尝试根据运行时模块映射信息，计算模块内偏移
       - 适用于 DLL / so / ASLR / PIE 等场景
    2. 若未启动调试器：
       - 回退到静态分析模式
       - 使用主映像（image base）作为基址计算偏移

    返回值示例：
    ModuleOffsetInfo(
        mode="debugger" | "static",
        module=模块名或 "image",
        base=使用的基址,
        offset=相对于基址的偏移
    )
    """
    # 当前光标所在的有效地址（EA）
    ea = ida_kernwin.get_screen_ea()
    if ea == idaapi.BADADDR:
        raise ValueError("当前光标位置无效（BADADDR）")

    # ----------------------------
    # 调试状态：优先使用模块偏移
    # ----------------------------
    if ida_dbg.is_debugger_on():
        modinfo = idaapi.modinfo_t()  # 统一使用idaapi，兼容不同IDA版本

        # 根据地址反查其所属的运行时模块
        if ida_dbg.get_module_info(ea, modinfo):
            # 清理模块名（去掉路径，只保留文件名）
            module_name = os.path.basename(modinfo.name) if modinfo.name else "unknown"
            return ModuleOffsetInfo(
                mode="debugger",
                module=module_name,
                base=modinfo.base,
                offset=ea - modinfo.base,
            )

    # --------------------------------
    # 静态状态：回退到 image base 偏移
    # --------------------------------
    image_base = idaapi.get_imagebase()
    module_path = ida_nalt.get_input_file_path()
    module_name = os.path.basename(module_path) if module_path else "image"

    return ModuleOffsetInfo(
        mode="static",
        module=module_name,
        base=image_base,
        offset=ea - image_base,
    )




def get_function_start_ea_by_offset(module: ModuleOffsetInfo) -> int:
    """
    根据模块基址和模块内偏移，获取该偏移所在的函数入口地址。

    设计目的：
    - 将类似「module base + offset」的 Frida/动态调试地址映射到 IDA 静态分析中的函数入口。
    - 支持偏移地址落在函数内部的情况，自动找到所属函数的起始地址。

    参数：
    - module : ModuleOffsetInfo
        包含模块基址（base）和模块内偏移（offset）的对象。

    返回值：
    - 函数起始地址（EA），如果该偏移不属于任何已识别函数，则返回 None。

    使用说明：
    - 先将模块内偏移转换为 IDA 中的绝对地址（EA）。
    - 通过 ida_funcs.get_func() 查找该 EA 所在函数。
    - 返回函数入口地址 func.start_ea。
    """
    # 将模块内偏移还原为 IDA 中的绝对地址
    ea = module.base + module.offset
    if ea == idaapi.BADADDR:
        return None

    # 获取该地址所属函数（允许地址位于函数内部）
    func = ida_funcs.get_func(ea)
    if not func:
        return None

    # 返回函数入口地址
    return func.start_ea


def get_func_prototype(func_ea: int) -> ida_typeinf.tinfo_t:
    """
    获取函数的原型信息
    :param func_ea: 函数起始地址
    :return: tinfo_t 对象，失败返回 None
    """
    if func_ea == idaapi.BADADDR:
        return None

    tif = ida_typeinf.tinfo_t()
    # 尝试获取函数类型信息（多种方式确保兼容性）
    if idaapi.get_tinfo(tif, func_ea):
        return tif
    if ida_typeinf.guess_tinfo(tif, func_ea):
        return tif
    return None


def build_func_desc() -> FuncDesc | None:
    """
    根据函数起始地址构造 FuncDesc 描述对象
    """
    # 获取函数所在模块信息
    module_offset_info = get_cursor_relative_offset()
    # 定位函数起始地址
    func_ea = get_function_start_ea_by_offset(module_offset_info)
    # 是否存在这个函数地址
    if func_ea:
        # 获取函数原型
        func_tinfo = get_func_prototype(func_ea)
        if func_tinfo and not func_tinfo.empty():
            # 获取函数详情
            funcdata = ida_typeinf.func_type_data_t()
            func_tinfo.get_func_details(funcdata)

            args: list[ArgDesc] = []

            ret_reg = ida_idp.get_reg_name(funcdata.retloc.reg1(), ptr_size)
            for idx in range(funcdata.size()):
                arg = funcdata[idx]
                loc = arg.argloc

                if loc.is_reg1():
                    reg = ida_idp.get_reg_name(loc.reg1(), ptr_size)
                elif loc.in_stack:
                    reg = "stack"
                args.append(
                    ArgDesc(
                        index=idx,
                        name=arg.name or f"arg{idx}",
                        ida_type=str(arg.type),
                        ida_real_type=BasicType(arg.type.get_realtype()).name,
                        mapToFridaType=IDA_TYPE_TO_FRIDA_TYPE_MAP[BasicType(arg.type.get_realtype()).name],
                        reg=reg
                    )
                )
            return FuncDesc(
                offset=func_ea - module_offset_info.base,
                name=ida_name.get_ea_name(func_ea),
                module=module_offset_info.module,
                ret_ida_type=str(funcdata.rettype),
                ret_ida_real_type=BasicType(funcdata.rettype.get_realtype()).name,
                rettypeMapToFridaType=IDA_TYPE_TO_FRIDA_TYPE_MAP[BasicType(funcdata.rettype.get_realtype()).name],
                ret_reg=ret_reg,
                args=args
            )
        else:
            print("警告：该函数无类型信息（未定义原型）")
            return None

    else:
        print("无效的函数地址")
        return None


#     将ida类型映射到frida类型
def ida_basictype_connect_to_fridatype(idaType: str) -> str:
    s = idaType.lower()  # 将输入转换为小写

    # 如果类型直接在 Frida 类型表中，则直接返回
    if s in FRIDA_TYPES:
        return s

    # 根据后缀进行映射
    for frida_type in FRIDA_TYPES:
        if s.endswith(frida_type):  # 比较后缀
            return frida_type

    # 如果没有找到匹配的类型，默认返回 pointer
    return "pointer"


# 生成映射表
def build_ida_basictype_to_frida_map():
    result = {}

    for bt in BasicType:
        name = bt.name  # BT_INT64
        suffix = name.split("_", 1)[-1]  # INT64

        frida_type = ida_basictype_connect_to_fridatype(suffix)
        result[name] = frida_type

    return result


# 生成当前版本IDA类型表
def generateIDABasicType():
    pattern = re.compile(r'^(BT_|BTF_)')
    # 初始化basic type 常量表
    bt_constants = {
        name: getattr(ida_typeinf, name)
        for name in dir(ida_typeinf)
        if pattern.match(name)
    }
    bt_constants_sorted = dict(sorted(bt_constants.items(), key=lambda x: x[1]))
    # BasicTypeTable = {}
    # for name, value in bt_constants.items():
    #     # 避免未来出现重复值时被覆盖（保守）
    #     BasicTypeTable.setdefault(value, []).append(name)
    print(bt_constants_sorted)


# 生成的 Frida 脚本
def generate_frida_script(func_desc: FuncDesc) -> str:
    """
    根据 FuncDesc 生成 Frida 脚本

    :param func_desc: FuncDesc 对象，包含函数信息
    :return: 生成的 Frida 脚本
    """
    script = []
    module_name = func_desc.module
    offset = func_desc.offset

    # 加载模块的基址
    script.append(f"var module_name = '{module_name}';")
    script.append(f"var offset = {hex(offset)};")
    script.append(f"var base_address = Process.findModuleByName(module_name);")
    script.append(f"if (base_address !== null) {{")
    script.append(f"    var target_address = base_address.base.add(offset);")
    script.append(f"    console.log('Hooking function: {func_desc.name} at address: ' + target_address);")

    script.append(f"\n    Interceptor.attach(target_address, {{")
    script.append(f"        onEnter: function(args) {{")
    script.append(f"            console.log('Function {func_desc.name} entered');")

    # 打印寄存器值
    for i, arg in enumerate(func_desc.args):
        script.append(
            f"            console.log('Register {arg.reg}: ' + this.context.{arg.reg.lower()});  // {arg.name} (register: {arg.reg})")

    script.append(f"\n            // 打印函数参数：")

    # # 简化处理：使用字典映射来自动选择对应类型的读取方法
    # frida_type_map = {
    #     "pointer": "readPointer",
    #     "int64": "readS64",
    #     "int": "readS32",
    #     "uint": "readU32",
    #     "bool": "readS8",
    #     "float": "readFloat",
    #     "double": "readDouble",
    #     "char": "readS8",
    #     "int8": "readS8",
    #     "uint8": "readU8",
    #     "int16": "readS16",
    #     "uint16": "readU16",
    #     "int32": "read32",
    #     "uint32": "readU32",
    #     "uint64": "readU64",
    #     "ulong": "readULong",
    #     "long": "readLong",
    #     "size_t": "readU32",
    #     "ssize_t": "readS32"
    # }

    # 打印参数值（根据 mapToFridaType 打印）
    for arg in func_desc.args:
        script.append(
            f"            console.log('{arg.name}: ' + args[{arg.index}]);  // {arg.name} ({arg.ida_type})")

    script.append(f"        }},")

    # 打印返回值寄存器及返回值
    script.append(f"        onLeave: function(retval) {{")
    if func_desc.ret_reg is not None:
        script.append(
            f"            console.log('Return Register {func_desc.ret_reg}: ' + this.context.{func_desc.ret_reg.lower() if func_desc.ret_reg else 'None'});  // {func_desc.ret_reg} (register)"
        )
        script.append(
            f"            console.log('Return value: ' + retval);  // {func_desc.ret_ida_type} (return type)"
        )
    else:
        script.append(
            f"            console.log('Return Register: None');  // {func_desc.ret_reg} (register)"
        )
        script.append(
            f"            console.log('Return value: None');  // {func_desc.ret_ida_type} (return type)"
        )

    script.append(f"        }}")
    script.append(f"    }});")
    script.append(f"}} else {{")
    script.append(f"    console.log('Module not found');")
    script.append(f"}}")

    return "\n".join(script)


def waterFrida() -> str | None:
    func_desc = build_func_desc()
    if func_desc is None:
        print("无效的函数描述")
        return None
    else:
        return generate_frida_script(func_desc)

def dump_runtime_module_segments():
    info = getRuntimeModuleInfo()
    if not info:
        print("[!] no runtime module")
        return

    out_path = r"C:\Users\water\Desktop\dump_" + os.path.basename(info.name)

    base = info.base
    end  = info.base + info.size

    buf = bytearray()
    print(f"[+] dumping module: {info.name}")
    print(f"    range: 0x{base:X} - 0x{end:X}")

    seg = ida_segment.get_first_seg()
    while seg:
        seg_start = seg.start_ea
        seg_end   = seg.end_ea

        # 只处理落在 module 范围内的 segment
        if seg_end <= base or seg_start >= end:
            seg = ida_segment.get_next_seg(seg_start)
            continue

        read_start = max(seg_start, base)
        read_end   = min(seg_end, end)
        size = read_end - read_start

        data = ida_bytes.get_bytes(read_start, size)
        if data:
            buf.extend(data)
            print(f"    dumped segment: 0x{read_start:X}-0x{read_end:X}")
        else:
            print(f"    skip unreadable: 0x{read_start:X}")

        seg = ida_segment.get_next_seg(seg_start)

    with open(out_path, "wb") as f:
        f.write(buf)

    print(f"[+] dump done: {out_path}")
    print(f"    total size: 0x{len(buf):X}")


class WaterDebugPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "WaterDebug - runtime helper"
    help = "w: eval expression | Ctrl+Shift+F: Frida | Alt+D: dump module"
    wanted_name = "WaterDebug"
    wanted_hotkey = ""

    def init(self):
        ida_kernwin.add_hotkey("w", self.on_eval)
        ida_kernwin.add_hotkey("Ctrl+Shift+F", self.on_frida)
        ida_kernwin.add_hotkey("Alt+D", self.on_dump)
        ida_kernwin.msg("[WaterDebug] loaded\n")
        return idaapi.PLUGIN_KEEP

    def term(self):
        ida_kernwin.msg("[WaterDebug] unloaded\n")

    # def run(self, arg):
    #     self.on_eval()

    def on_eval(self):
        expr = ida_kernwin.ask_str("", 0, "WaterDebug expression")
        if not expr:
            return
        try:
            value = eval_expression(expr)
            ida_kernwin.msg(f"[WaterDebug] {expr} = 0x{value:X}\n")
            ida_kernwin.jumpto(value)
        except Exception as e:
            ida_kernwin.warning(f"[WaterDebug] eval failed: {e}")

    def on_frida(self):
        try:
            script = waterFrida()
            pyperclip.copy(script)
            ida_kernwin.msg("[WaterDebug] Frida script copied\n")
        except Exception as e:
            ida_kernwin.warning(f"[WaterDebug] Frida failed: {e}")

    def on_dump(self):
        try:
            dump_runtime_module_segments()
            ida_kernwin.msg("[WaterDebug] dump triggered\n")
        except Exception as e:
            ida_kernwin.warning(f"[WaterDebug] dump failed: {e}")


def PLUGIN_ENTRY():
    return WaterDebugPlugin()