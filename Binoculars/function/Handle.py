import ida_kernwin
import ida_hexrays
import ida_bytes
import ida_ida
import idc
import idautils
import ida_funcs
import ida_entry
import idaapi
import ida_gdl
import ida_lines
import ida_idaapi
import ida_nalt
import ida_typeinf
import ida_xref
import functools
import ida_name
import ida_lines
import re
import json
import struct
from typing import Any, Callable, get_type_hints, TypedDict, Optional, Annotated, TypeVar, Generic
from pydantic import Field
T = TypeVar("T")



ai_commands = {}
def ai_command(func):  
    params_schema = {
        "name": func.__name__,
        "description": func.__doc__.strip(),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    for name, param in func.__annotations__.items():
        if name == 'return':
            continue
        if hasattr(param, '__metadata__'):
            desc = param.__metadata__[0].description
            params_schema['parameters']['properties'][name] = {
                "type": param.__origin__.__name__,
                "description": desc
            }
            if param.__origin__ != Optional:
                params_schema['parameters']['required'].append(name)
    ai_commands[func.__name__] = params_schema
    return func

####################导入导出相关##############################
from typing import Optional, TypedDict, List
from pydantic import Field

class ImportItem(TypedDict):
    ea: str
    name: str
    module: str

class PagedImports(TypedDict):
    total: int
    next_offset: Optional[int]
    items: list[ImportItem]
    
class ExportItem(TypedDict):
    address: str
    name: Optional[str]
    ordinal: Optional[int]

class PagedExports(TypedDict):
    total: int
    items: List[ExportItem]

##################################################

class FuncHandle(object): 
    def __init__(self, assistant_widget):
        self.assistant_widget = assistant_widget
        
    def PrintOutput(self, output_str):
        self.assistant_widget.PrintOutput(output_str)
     
    @classmethod
    def get_ai_prompts(cls, format: str = "markdown"):
        if format == "markdown":
            return cls._generate_markdown()
        elif format == "json":
            return json.dumps(ai_commands, indent=2)
        elif format == "openai":
            return cls._generate_openai_schema()
        else:
            raise ValueError(f"Unsupported format: {format}")

    @classmethod
    def _generate_markdown(cls):
        output = ["## Available Commands"]
        for cmd,value in ai_commands.items():
          output.append(f"### `{value['name']}`")
          output.append(f"{value['description']}\n")
          output.append("**Parameters:**")
          for param, meta in value['parameters']['properties'].items():
            required = "(Required)" if param in value['parameters'].get('required', []) else "(Optional)"
            output.append(f"- `{param}`: {meta['description']} {required}")
          output.append("\n---")
        return "\n".join(output)
    
    @classmethod
    def _generate_openai_schema(cls):
        return [{
            "type": "function",
            "function": {
                "name": cmd["name"],
                "description": cmd["description"],
                "parameters": cmd["parameters"]
            }
        } for cmd in ai_commands.values()]
    
    @ai_command
    def do_nothing(self) -> str:
        """
        Do nothing. Use it when a series of tasks are completed.
        """
        return 
        
########################################################################
    class Metadata(TypedDict):
        path: str
        module: str
        base: str
        size: str
        md5: str
        sha256: str
        crc32: str
        filesize: str

    def get_image_size(self):
        try:
            info = idaapi.get_inf_structure()
            omin_ea = info.omin_ea
            omax_ea = info.omax_ea
        except AttributeError:
            import ida_ida
            omin_ea = ida_ida.inf_get_omin_ea()
            omax_ea = ida_ida.inf_get_omax_ea()
        # Bad heuristic for image size (bad if the relocations are the last section)
        image_size = omax_ea - omin_ea
        # Try to extract it from the PE header
        header = idautils.peutils_t().header()
        if header and header[:4] == b"PE\0\0":
            image_size = struct.unpack("<I", header[0x50:0x54])[0]
        return image_size
    
    # 获取当前 IDB 的元数据
    @ai_command
    def get_metadata(self) -> Metadata:
        """Get metadata about the current IDB"""
        # Fat Mach-O binaries can return a None hash:
        # https://github.com/mrexodia/ida-pro-mcp/issues/26
        def hash(f):
            try:
                return f().hex()
            except:
                return None
        return {
            "path": idaapi.get_input_file_path(),
            "module": idaapi.get_root_filename(),
            "base": hex(idaapi.get_imagebase()),
            "size": hex(self.get_image_size()),
            "md5": hash(ida_nalt.retrieve_input_file_md5),
            "sha256": hash(ida_nalt.retrieve_input_file_sha256),
            "crc32": hex(ida_nalt.retrieve_input_file_crc32()),
            "filesize": hex(ida_nalt.retrieve_input_file_size()),
        }
    
    class Function(TypedDict):
        start_address: int
        end_address: int
        name: str
        prototype: Optional[str]

    def get_prototype(self, fn: ida_funcs.func_t) -> Optional[str]:
        try:
            prototype: ida_typeinf.tinfo_t = fn.get_prototype()
            if prototype is not None:
                return str(prototype)
            else:
                return None
        except AttributeError:
            try:
                return idc.get_type(fn.start_ea)
            except:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, fn.start_ea):
                    return str(tif)
                return None
        except Exception as e:
            print(f"Error getting function prototype: {e}")
            return None


    def get_function(self, address: int, *, raise_error=True) -> Optional[Function]:
        fn = idaapi.get_func(address)
        if fn is None:
            if raise_error:
                raise IDAError(f"No function found at address {address}")
            return None

        try:
            name = fn.get_name()
        except AttributeError:
            name = ida_funcs.get_func_name(fn.start_ea)
        return {
            "address": fn.start_ea,
            "end_address": fn.end_ea,
            "name": name,
            "prototype": self.get_prototype(fn),
        }

        
    # 获取入口点
    @ai_command
    def get_entry_points(
        self
    ) -> list:
        """
        Get all entry points in the database
        """
        result = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            address = ida_entry.get_entry(ordinal)
            func = self.get_function(address, raise_error=False)
            if func is not None:
                result.append(func)
        return result
    
    # 获取当前地址
    def get_current_address(self) -> str:
        """Get the address currently selected by the user"""
        return hex(idaapi.get_screen_ea())
    
        
    def get_type_ea(self, ea):
        flag_types = []
        flags = ida_bytes.get_flags(ea)
        if idc.is_code(flags):
            flag_types.append("CODE")
        if idc.is_data(flags):
            flag_types.append("DATA")
        if idc.is_unknown(flags):
            flag_types.append("UNKNOWN")
        return f"Flags: {' | '.join(flag_types)}"
    
    # 确定给定地址处的数据类型和大小
    @ai_command
    def get_address_type(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> str:
        """
        Get the type of the address.
        """
        try:
            address = int(address, 16)
            flag_types = self.get_type_ea(address)
            size = idc.get_item_size(address)
            type_info = idc.get_type(address)
            if type_info:
                size_type = type_info
            else:
                size_type = {
                    1: "byte",
                    2: "word",
                    4: "dword",
                    8: "qword",
                    16: "oword"
                }.get(size, f"Unknown size ({size} bytes)")
            
            return f"Flags: {' | '.join(flag_types)}, Size: {size} bytes ({size_type})"
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 列出二进制文件中所有段的权限和大小。
    @ai_command
    def get_segments(self) -> list:
        """List all segments in the binary with permissions and size."""
        segs = []
        for seg in idautils.Segments():
            s = idaapi.getseg(seg)
            segs.append({
                "name": idaapi.get_segm_name(s),
                "start": hex(s.start_ea),
                "end": hex(s.end_ea),
                "size": s.size(),
                "perms": f"{'R' if s.perm & idaapi.SEGPERM_READ else '-'}"
                         f"{'W' if s.perm & idaapi.SEGPERM_WRITE else '-'}"
                         f"{'X' if s.perm & idaapi.SEGPERM_EXEC else '-'}"
            })
        return segs
    
########################################################################函数

    
    # 列出所有函数
    @ai_command
    def list_functions(self) -> list[Function]:
        """List all functions in the database"""
        return [get_function(address) for address in idautils.Functions()]

    # 获取当前函数信息
    def get_current_function(self) -> dict[Function]:
        """Get the function currently selected by the user"""
        return self.get_function(idaapi.get_screen_ea())

    def refresh_decompiler_ctext(self, function_address: int):
        error = ida_hexrays.hexrays_failure_t()
        cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(function_address, error, ida_hexrays.DECOMP_WARNINGS)
        if cfunc:
            cfunc.refresh_func_ctext()

    # 函数重命名
    @ai_command
    def rename_function(
        self,
        address: Annotated[str, Field(description="Hex address of the function to rename")],
        new_name: Annotated[str, Field(description="New name for the function")]
    ) -> str:
        """Rename a function"""
        try:
            function_address = int(address, 16)
            fn = idaapi.get_func(function_address)
            if not fn:
                return f"No function found at address {function_address}"
            if not idaapi.set_name(fn.start_ea, new_name):
               return f"Failed to rename function {fn.start_ea} to {new_name}"
            self.refresh_decompiler_ctext(fn.start_ea)
            return f"Successfully to rename function {fn.start_ea} to {new_name}"
        except Exception as e:
            return f"Error: {str(e)}"

    # 获取包含给定地址的函数的起始和结束地址
    @ai_command
    def get_function_start_end_address(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> dict:
        """
        Get the start and end address of the function at the specified address.
        """
        try:
            ea = int(address, 16)
            function = idaapi.get_func(ea)
            if function:
                return {
                    "start": hex(function.start_ea),
                    "end": hex(function.end_ea)
                }
            return {"error": f"No function at {hex(ea)}"}
        except Exception as e:
            return {"error": str(e)}
            
            
    def get_name_info(self):
        name_info = []
        for i in range(ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            name = ida_name.get_short_name(ea)
            name_info.append((name, hex(ea)))
        return name_info

    def search_name(self, keyword):        
        search_results = []
        
        functions = self.get_name_info()
        for name, ea in functions:
            if keyword.lower() in name.lower():
                search_results.append((name, ea))
        
        return search_results
    
    # 搜索名称中包含指定关键字的函数
    @ai_command
    def get_addresses_of_name(
        self,
        name: Annotated[str, Field(description="Search name")]
    ) -> list:
        """
        Search for a name as a parameter in ida name list and get all addresses with that name in the form of a list.
        """
        try:
            r = self.search_name(name)
            return r
        except Exception as e:
            return f"Error: {str(e)}"
    
    
    DEMANGLED_TO_EA = {}
    def create_demangled_to_ea_map(self):
        for ea in idautils.Functions():
            # Get the function name and demangle it
            # MNG_NODEFINIT inhibits everything except the main name
            # where default demangling adds the function signature
            # and decorators (if any)
            demangled = idaapi.demangle_name(
                idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
            if demangled:
                DEMANGLED_TO_EA[demangled] = ea
     
    def parse_address(self, address: str) -> int:
        try:
            return int(address, 0)
        except ValueError:
            for ch in address:
                if ch not in "0123456789abcdefABCDEF":
                    raise IDAError(f"Failed to parse address: {address}")
            raise IDAError(f"Failed to parse address (missing 0x prefix): {address}")
    
    # 通过函数名字获取函数
    @ai_command
    def get_function_by_name(
        self,
        name: Annotated[str, Field(description="Name of the function to get")]
    ) -> Function:
        """Get a function by its name"""
        function_address = idaapi.get_name_ea(idaapi.BADADDR, name)
        if function_address == idaapi.BADADDR:
            # If map has not been created yet, create it
            if len(DEMANGLED_TO_EA) == 0:
                self.create_demangled_to_ea_map()
            # Try to find the function in the map, else raise an error
            if name in DEMANGLED_TO_EA:
                function_address = DEMANGLED_TO_EA[name]
            else:
                raise IDAError(f"No function found with name {name}")
        return self.get_function(function_address)
    
    # 通过地址获取函数
    @ai_command
    def get_function_by_address(
        self,
        address: Annotated[str, Field(description="Address of the function to get")]
    ) -> Function:
        """Get a function by its address"""
        return self.get_function(self.parse_address(address))
    
########################################################################字符串


    class Page(TypedDict, Generic[T]):
        data: list[T]
        next_offset: Optional[int]
        
    def paginate(self, data: list[T], offset: int, count: int) -> Page[T]:
        if count == 0:
            count = len(data)
        next_offset = offset + count
        if next_offset >= len(data):
            next_offset = None
        return {
            "data": data[offset:offset+count],
            "next_offset": next_offset,
        }
        
    class String(TypedDict):
        address: str
        length: int
        type: str
        string: str

    def get_strings(self) -> list:
        strings = []
        for item in idautils.Strings():
            string_type = "C" if item.strtype == 0 else "Unicode"
            try:
                string = str(item)
                if string:
                    strings.append({
                        "address": hex(item.ea),
                        "length": item.length,
                        "type": string_type,
                        "string": string
                    })
            except:
                continue
        return strings
    
    # 获取所有字符串
    @ai_command
    def list_strings(
        self,
        offset: Annotated[int, Field(description="Offset to start listing from (start at 0)")],
        count: Annotated[int, Field(description="Number of strings to list (100 is a good default, 0 means remainder)")]
    ) -> Page[String]:
        """List all strings in the database (paginated)"""
        try:
            strings = self.get_strings()
            return self.paginate(strings, offset, count)
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 搜索包含给定模式的字符串
    @ai_command
    def search_strings(
        self,
        pattern_str: Annotated[str, Field(description="The regular expression to match(The generated regular expression includes case by default)")],
        offset: Annotated[int, Field(description="Offset to start listing from (start at 0)")],
        count: Annotated[int, Field(description="Number of strings to list (100 is a good default, 0 means remainder)")]
)   -> Page[String]:
        """Search for strings that satisfy a regular expression"""
        strings = self.get_strings()
        try:
            pattern = re.compile(pattern_str)
            matched_strings = [s for s in strings if s["string"] and re.search(pattern, s["string"])]
            return paginate(matched_strings, offset, count)
        except Exception as e:
            return f"Error: {str(e)}"


########################################################################反汇编

    # 在指定的反汇编地址添加或修改可重复注释
    @ai_command
    def set_disassembly_comment(
        self,
        address: Annotated[str, Field(description="Hex address")],
        comment: Annotated[str, Field(description="Comment content")]
    ) -> str:
        """
        Set a comment at the specified address.
        """
        try:
            ea = int(address, 16)
            idc.set_cmt(ea, comment, 1)
            return f"Set comment at {hex(ea)}: {comment}"
        except Exception as e:
            return f"Error: {str(e)}"
        
    
    # 获取指定地址范围内的反汇编指令
    @ai_command
    def get_disassembly(
        self,
        start_address: Annotated[str, Field(description="Start address (supports hex or decimal string)")],
        end_address: Annotated[str, Field(description="End address (optional, uses current selection if not provided)")]
    ) -> str:
        """
        Gets the disassembly from start address to end address.
        """       
        try:
            start_address = int(start_address, 16)
            end_address = int(end_address, 16)
            if start_address and end_address and start_address != end_address:
                disassembly = ""
                while start_address < end_address:
                    disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                    start_address = idc.next_head(start_address)
                return disassembly
            else:
                start_address = idc.read_selection_start()
                end_address = idc.read_selection_end()
                disassembly = ""
                for ea in idautils.Heads(start, end):
                    text = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                    disassembly += f"{hex(ea)}: {text}\n"
                return disassembly
        except Exception as e:
            return f"Error: {str(e)}"
            
            
    # 获取选定范围内的反汇编指令
    @ai_command
    def get_selected_disassembly(self) -> str:
        """
        Gets the selected disassembly.
        """
        try:
            start = idc.read_selection_start()
            end = idc.read_selection_end()
            
            if start == idc.BADADDR or end == idc.BADADDR:
                return "No selection or invalid selection."
            
            disassembly = ""
            for ea in idautils.Heads(start, end):
                text = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                disassembly += f"{hex(ea)}: {text}\n"
            return disassembly
        except Exception as e:
            return f"Error: {str(e)}"
            

    # 获取特定函数的反汇编指令
    @ai_command
    def get_disassembly_function(
        self,
        name: Annotated[str, Field(description="Function name")]
    ) -> str:
        """
        Get disassembly instructions of specified function
        """
        try:
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                function = idaapi.get_func(address)
                start_address = function.start_ea
                end_address = function.end_ea

                disassembly = ""
                while start_address < end_address:
                    disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                    start_address = idc.next_head(start_address)
                return disassembly
            return f"No function found: {name}"
        except Exception as e:
            return f"Error: {str(e)}"
            
########################################################################反编译

    # 反编译给定地址处的函数的代码
    @ai_command
    def decompile_address(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> str:
        """
        Decompile the function at the specified address.
        """
        try:
            ea = int(address, 16)
            function = idaapi.get_func(ea)
            if function:
                decompiled_code = idaapi.decompile(function)
                return str(decompiled_code) if decompiled_code else "Decompile failed"
            return f"No function at {hex(ea)}"
        except Exception as e:
            return f"Error: {str(e)}"
            

    # 反编译由其名称指定的函数
    @ai_command
    def decompile_function(
        self,
        name: Annotated[str, Field(description="Function name")]
    ) -> str:
        """
        Decompile function by name
        """
        try:
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                function = idaapi.get_func(address)
                if function:
                    decompiled_code = idaapi.decompile(function)
                    return str(decompiled_code) if decompiled_code else "Decompile failed"
            return f"Function not found: {name}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 重命名反编译代码中特定地址处的局部变量
    @ai_command
    def rename_local_variable(
        self,
        address: Annotated[str, Field(description="Address of the function containing the variable")],        
        old_name: Annotated[str, Field(description="Current name of the variable")],
        new_name: Annotated[str, Field(description="New name for the variable")]
    ) -> str:
        """
        Rename a local variable in a function
        """
        try:
            function_address = int(address, 16)
            func = idaapi.get_func(function_address)
            if not func:
                return f"No function found at address {address}"
            if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
                return f"Failed to rename local variable {old_name} in function {func.start_ea}"
            self.refresh_decompiler_ctext(func.start_ea)
            return f"Successfully to rename local variable {old_name} in function {func.start_ea}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    '''
    # 反汇编由地址指定的函数
    @ai_command
    def disassemble_function(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> str:
        """
        Get assembly code (address: instruction; comment) for a function
        """
        try:
            address = int(address, 16)
            func = idaapi.get_func(address)
            if not func:
                raise IDAError(f"No function found at address {address}")

            # TODO: add labels
            disassembly = ""
            for address in ida_funcs.func_item_iterator_t(func):
                if len(disassembly) > 0:
                    disassembly += "\n"
                disassembly += f"{address}: "
                disassembly += idaapi.generate_disasm_line(address, idaapi.GENDSM_REMOVE_TAGS)
                comment = idaapi.get_cmt(address, False)
                if not comment:
                    comment = idaapi.get_cmt(address, True)
                if comment:
                    disassembly += f"; {comment}"
            return disassembly
        except Exception as e:
            return f"Error: {str(e)}"
    '''   
    
    def decompile_checked(self, address: int) -> ida_hexrays.cfunc_t:
        if not ida_hexrays.init_hexrays_plugin():
            raise IDAError("Hex-Rays decompiler is not available")
        error = ida_hexrays.hexrays_failure_t()
        cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
        if not cfunc:
            message = f"Decompilation failed at {address}"
            if error.str:
                message += f": {error.str}"
            if error.errea != idaapi.BADADDR:
                message += f" (address: {error.errea})"
            raise IDAError(message)
        return cfunc
    
    # 设置反编译注释
    @ai_command
    def set_decompiler_comment(
        self,      
        address: Annotated[str, Field(description="Address in the function to set the comment for")],
        comment: Annotated[str, Field(description="Comment text (not shown in the pseudocode")]
    ) -> str:
        """
        Set a comment for a given address in the function pseudocode
        """
        try:
            address = int(address, 16)
            cfunc = self.decompile_checked(address)

            # 函数入口注释的特殊情况
            if address == cfunc.entry_ea:
                idc.set_func_cmt(address, comment, True)
                cfunc.refresh_func_ctext()
                return f"Set comment at {address}: {comment}"

            eamap = cfunc.get_eamap()
            if address not in eamap:
                raise IDAError(f"Failed to set comment at {address}")
            nearest_ea = eamap[address][0].ea

            # 删除现有的孤立评论
            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            # 通过尝试所有可能的项目类型来设置评论
            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    return f"Set comment at {address}: {comment}"
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            return f"Failed to set comment at {address}"
        except Exception as e:
            return f"Error: {str(e)}"
        
########################################################################交叉引用
    
    # 获取到指定地址的交叉引用  
    @ai_command
    def get_xrefs_to(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> list:
        """
        Get the cross-references to the specified address.
        """
        try:
            address = int(address, 16)
            xrefs = []
            for xref in idautils.XrefsTo(address, 0):
                xrefs.append((hex(xref.frm), self.get_type_ea(xref.frm), idautils.XrefTypeName(xref.type)))
            return xrefs
        except Exception as e:
            return f"Error: {str(e)}"

    # 获取从指定地址的交叉引用
    @ai_command
    def get_xrefs_from(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> list:
        """
        Get the cross-references from the specified address.
        """
        try:
            ea = int(address, 16)
            xrefs = []
            for xref in idautils.XrefsFrom(ea, 0):
                xrefs.append((
                    hex(xref.to), 
                    self.get_type_ea(xref.to), 
                    idautils.XrefTypeName(xref.type)
                ))
            return xrefs
        except Exception as e:
            return [f"Error: {str(e)}"]

    # 获取到指定地址处的函数内地址的交叉引用
    @ai_command
    def get_func_xrefs_to(
        self,
        address: Annotated[str, Field(description="Hex address")]
    ) -> list:
        """
        Get the details of all cross-references to the specified function.
        """
        try:
            ea = int(address, 16)
            if ea == idc.BADADDR:
                return [f"Invalid address: {hex(ea)}"]

            xrefs = []
            for xref in idautils.XrefsTo(ea, 0):
                xrefs.append((
                    hex(xref.frm), 
                    self.get_type_ea(xref.frm), 
                    idautils.XrefTypeName(xref.type)
                ))
            return xrefs
        except Exception as e:
            return [f"Error: {str(e)}"]

########################################################################

    # 获取选中范围的代码的栈字符串
    @ai_command
    def get_stack_string_of_the_selected_range_of_code(self) -> dict:
        """
        Extract stack strings from selected code range
        """
        try:
            disassembly_str = self.get_selected_disassembly()
            if not disassembly_str:
                return {"error": "No valid selection"}

            hex_list = re.findall(r',\s*([0-9A-Fa-f]+h)', disassembly_str)
            result_str = ''
            
            for hex_str in hex_list:
                little_endian_bytes = bytes.fromhex(hex_str.replace("h",""))
                big_endian_bytes = little_endian_bytes[::-1]
                filtered_hex_str = ''.join(
                    chr(int_data) 
                    for int_data in big_endian_bytes 
                    if int_data != 0
                )
                result_str += filtered_hex_str 
                
            return {"result": result_str}
        except Exception as e:
            return {"error": str(e)}
    

########################################################################结构体操作
    
    # 创建具有指定成员的新结构
    @ai_command
    def create_structure(
        self,
        name: Annotated[str, Field(description="Structure name")],
        members: Annotated[list, Field(description="List of tuples (offset, type, name)")]
    ) -> str:
        """Create a new structure with specified members"""
        try:
            sid = idaapi.add_struc(idaapi.BADADDR, name)
            if sid == idaapi.BADADDR:
                return f"Structure {name} already exists"
            
            for offset, mtype, mname in members:
                if not idaapi.add_struc_member(sid, mname, offset, mtype, None, 0):
                    return f"Failed to add member {mname} at offset {offset}"
            
            idaapi.refresh_idaview_anyway()
            return f"Created structure {name} with {len(members)} members"
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 将结构类型应用于指定地址
    @ai_command
    def apply_structure(
        self,
        address: Annotated[str, Field(description="Hex address")],
        struct_name: Annotated[str, Field(description="Structure name")]
    ) -> str:
        """Apply structure type to specified address"""
        try:
            ea = int(address, 16)
            tid = idaapi.get_struc_id(struct_name)
            if tid == idaapi.BADADDR:
                return f"Structure {struct_name} not found"
            
            if not idaapi.create_struct(ea, -1, tid):
                return f"Failed to apply structure at {hex(ea)}"
            
            return f"Applied {struct_name} structure at {hex(ea)}"
        except Exception as e:
            return f"Error: {str(e)}"

######################################################################## 枚举操作
    
    # 创建具有指定成员的新枚举
    @ai_command
    def create_enum(
        self,
        name: Annotated[str, Field(description="Enumeration name")],
        members: Annotated[dict, Field(description="Dictionary {name: value}")]
    ) -> str:
        """Create a new enumeration with specified members"""
        try:
            eid = idaapi.add_enum(idaapi.BADADDR, name, 0)
            if eid == idaapi.BADADDR:
                return f"Enum {name} already exists"
            
            for ename, evalue in members.items():
                if not idaapi.add_enum_member(eid, ename, evalue, -1):
                    return f"Failed to add member {ename} with value {evalue}"
            
            return f"Created enum {name} with {len(members)} members"
        except Exception as e:
            return f"Error: {str(e)}"


######################################################################## 导入表/导出表


    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _collect_imports() -> list[ImportItem]:
        """Snapshot all imported functions from the IDB (runs on UI thread, cached)."""
        idaapi.auto_wait()  # Ensure analysis is complete
        results: list[ImportItem] = []
        qty = ida_nalt.get_import_module_qty()

        for mod_idx in range(qty):
            module_name = ida_nalt.get_import_module_name(mod_idx) or f"module_{mod_idx}"

            def imp_cb(ea, name, ordinal):
                results.append({
                    "ea": hex(ea),
                    "name": name or f"ord_{ordinal}",
                    "module": module_name,
                })
                return 1  # Continue enumeration

            ida_nalt.enum_import_names(mod_idx, imp_cb)

        return results

    # 获取导入函数
    @ai_command
    def get_imports(
        self,
        limit: Annotated[int, Field(description="Maximum number of imports to return (positive integer, default 50)")] = 50,
        offset: Annotated[int, Field(description="Offset to start from (non-negative, default 0)")] = 0,
        module_filter: Annotated[Optional[str], Field(description="Filter by module name (case-insensitive substring, e.g., 'kernel32')")] = None
    ) -> PagedImports:
        """
        Get paginated imported functions with optional module filtering.
        Useful for identifying dependencies and API usage.
        """
        try:
            if limit <= 0:
                return {
                    "total": 0,
                    "next_offset": None,
                    "items": [],
                    "error": "limit must be a positive integer"
                }
            if offset < 0:
                return {
                    "total": 0,
                    "next_offset": None,
                    "items": [],
                    "error": "offset must be non-negative"
                }

            all_imports = self._collect_imports()

            # Apply module filter if provided
            if module_filter and module_filter.strip():
                filter_norm = module_filter.strip().lower()
                filtered_imports = [
                    item for item in all_imports
                    if filter_norm in item["module"].lower()
                ]
            else:
                filtered_imports = all_imports

            total = len(filtered_imports)
            start = min(offset, total)
            end = min(start + limit, total)
            items = filtered_imports[start:end]
            next_offset = end if end < total else None

            return {
                "total": total,
                "next_offset": next_offset,
                "items": items
            }

        except Exception as e:
            return {
                "total": 0,
                "next_offset": None,
                "items": [],
                "error": f"Failed to retrieve imports: {str(e)}"
            }
    
    # 获取导出表
    @ai_command
    def get_exports(self) -> PagedExports:
        """
        Get all exported functions with address, name, and ordinal.
        Useful for analyzing the public interface of a DLL.
        """
        try:
            exports: List[ExportItem] = []
            for entry in idautils.Entries():
                # entry 格式: (index, ordinal, ea) 或 (index, ordinal, ea, name)
                if len(entry) < 3:
                    continue
                _, ordinal, ea = entry[0], entry[1], entry[2]
                name = None
                if len(entry) >= 4:
                    name = entry[3]
                    if not name:
                        name = None  # 统一空值为 None

                exports.append({
                    "address": hex(ea),
                    "name": name,
                    "ordinal": ordinal if ordinal != 0xFFFF else None  # 无效 ordinal 处理
                })

            return {
                "total": len(exports),
                "items": exports
            }

        except Exception as e:
            return {
                "total": 0,
                "items": [],
                "error": f"Failed to retrieve exports: {str(e)}"
            }



########################################################################字符串处理
    
    # 查找字符串
    @ai_command
    def find_strings(
        self,
        min_length: Annotated[int, Field(description="Minimum string length")] = 5
    ) -> list:
        """Find all ASCII/Unicode strings"""
        results = []
        for s in idautils.Strings():
            try:
                if s.length >= min_length:
                    str_content = idc.get_strlit_contents(s.ea)
                    results.append({
                        "address": hex(s.ea),
                        "type": "ASCII" if s.strtype == 0 else "UNICODE",
                        "content": str_content.decode(errors='replace')
                    })
            except:
                continue
        return results
    
    # 重命名字符串
    @ai_command
    def rename_string(
        self,
        address: Annotated[str, Field(description="Hex address")],
        new_name: Annotated[str, Field(description="New string name")]
    ) -> str:
        """Rename a string at specified address"""
        try:
            ea = int(address, 16)
            if idc.create_strlit(ea, idc.BADADDR, idc.STRTYPE_C):
                return f"Renamed string at {hex(ea)} to {new_name}"
            return f"Failed to rename string at {hex(ea)}"
        except Exception as e:
            return f"Error: {str(e)}"


########################################################################重定位处理
    
    # 获取所有重定位条目
    @ai_command
    def get_relocations(self) -> list:
        """Get all relocation entries"""
        return [
            {
                "address": hex(r.ea),
                "type": r.type,
                "symbol": idc.get_name(r.sym)
            } 
            for r in idautils.Relocations()
        ]


########################################################################二进制修补
    
    # 修补指定地址的字节
    @ai_command
    def patch_bytes(
        self,
        address: Annotated[str, Field(description="Hex address")],
        new_bytes: Annotated[str, Field(description="Hex string (e.g. 90 90 CC)")]
    ) -> str:
        """Patch bytes at specified address"""
        try:
            ea = int(address, 16)
            byte_data = bytes.fromhex(new_bytes.replace(" ", ""))
            ida_bytes.patch_bytes(ea, byte_data)
            idaapi.refresh_idaview_anyway()
            return f"Patched {len(byte_data)} bytes at {hex(ea)}"
        except Exception as e:
            return f"Error: {str(e)}"

 
########################################################################堆栈变量处理
    
    # 重命名堆栈变量
    @ai_command
    def rename_stack_variable(
        self,
        address: Annotated[str, Field(description="Function address")],
        offset: Annotated[int, Field(description="Stack offset")],
        new_name: Annotated[str, Field(description="New variable name")]
    ) -> str:
        """Rename a stack variable"""
        try:
            func_ea = int(address, 16)
            cfunc = self.decompile_checked(func_ea)
            
            for var in cfunc.lvars:
                if var.is_stk_var() and var.get_stkoff() == offset:
                    var.name = new_name
                    cfunc.save_local_types()
                    cfunc.refresh_func_ctext()
                    return f"Renamed stack variable at offset {offset} to {new_name}"
            
            return f"No stack variable found at offset {offset}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 设置堆栈变量类型
    @ai_command
    def set_stack_variable_type(
        self,
        address: Annotated[str, Field(description="Function address")],
        offset: Annotated[int, Field(description="Stack offset")],
        new_type: Annotated[str, Field(description="New type definition")]
    ) -> str:
        """Set stack variable type"""
        try:
            func_ea = int(address, 16)
            cfunc = self.decompile_checked(func_ea)
            
            tif = ida_typeinf.tinfo_t()
            if not tif.parse(new_type):
                return f"Invalid type definition: {new_type}"
            
            for var in cfunc.lvars:
                if var.is_stk_var() and var.get_stkoff() == offset:
                    var.tif = tif
                    cfunc.save_local_types()
                    cfunc.refresh_func_ctext()
                    return f"Set type for stack variable at offset {offset} to {new_type}"
            
            return f"No stack variable found at offset {offset}"
        except Exception as e:
            return f"Error: {str(e)}"

            
    
########################################################################功能性函数
    
    # 获取当前函数功能并生成注释(与RenameFunc.py功能相同)
    @ai_command
    def analyze_current_function_and_comment(
        self,
        default_model: Annotated[str, Field(description="Analysis model to use")] = "default"
    ) -> int:
        """
        Analyze current function and generate intelligent comments
        """
        from Binoculars.function.ExplainFunc import comment_callback 
        from Binoculars.config.config import get_current_language
        current_language = get_current_language()
        
        try:
            widget = ida_kernwin.get_current_widget()  # 获取当前活动的 widget
            if ida_kernwin.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
                func_ea = idaapi.get_screen_ea()
                ida_hexrays.open_pseudocode(func_ea, 0)  # 打开或激活反编译窗口
                widget = ida_kernwin.get_current_widget()  # 重新获取 widget
            
            decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
            messages,systemprompt = {},""
            default_model.query_model_async(
            "Can you explain the purpose of the following C function and suggest a better name for it? No need for an improved version or other information! Please reply in {current_language}!\n{decompiler_output}".format(decompiler_output=str(decompiler_output),current_language = current_language),messages,systemprompt,
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=widget))
            return 1
        except Exception as e:
            return f"Error: {str(e)}" 
    
    # 查找常见的 API 使用模式（网络、文件、加密等）
    @ai_command
    def find_api_patterns(self) -> dict:
        """
        Find common API usage patterns (network, file, crypto, etc.) by analyzing imported functions.
        """
        patterns = {
            "network": ["socket", "connect", "send", "recv", "WSA", "Http", "Internet", "URL"],
            "file": ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "fopen", "fwrite", "fread"],
            "registry": ["RegOpenKey", "RegSetValue", "RegQueryValue", "RegCreateKey"],
            "crypto": ["Crypt", "AES", "RSA", "SHA", "MD5", "EVP", "Digest", "Cipher", "BCRYPT"],
            "process": ["CreateProcess", "WinExec", "system", "ShellExecute", "CreateThread"],
            "debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString"],
            "injection": ["WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "NtMapViewOfSection"],
            "stealth": ["Hide", "Stealth", "Melt", "SelfDelete"]
        }

        try:
            imports_result = self.get_imports()
            items = imports_result.get("items", [])
            
            matches = {}
            for category, apis in patterns.items():
                hits = []
                for item in items:
                    # item: {"ea": "0x...", "name": "...", "module": "..."}
                    api_name = item["name"].lower()
                    module_name = item["module"].lower()
                    
                    for keyword in apis:
                        if keyword.lower() in api_name or keyword.lower() in module_name:
                            hits.append({
                                "api": item["name"],
                                "module": item["module"],
                                "address": item["ea"]
                            })
                            break  # 找到就跳出，避免重复添加
                
                if hits:
                    matches[category] = hits

            return {
                "total_matches": len(matches),
                "patterns": matches
            }

        except Exception as e:
            return {
                "error": f"Failed to analyze API patterns: {str(e)}"
            }

