import ida_kernwin
import ida_hexrays
import ida_bytes
import ida_ida
import idc
import idautils
import idaapi
import functools
import ida_name

class FuncHandle(): 
    def __init__(self, assistant_widget):
        self.assistant_widget = assistant_widget

    def PrintOutput(self, output_str):
        self.assistant_widget.PrintOutput(output_str)

    # 计算IDC表达式
    def handle_eval_idc(self, args):
        try:
            idc_expression = args["idc_expression"]
            result = idc.eval_idc(idc_expression)
            return result
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 获取指定地址范围内的反汇编指令
    def handle_get_disassembly(self, args):
        try:
            start_address = int(args["start_address"], 16)
            end_address = int(args["end_address"], 16)

            disassembly = ""
            while start_address < end_address:
                disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                start_address = idc.next_head(start_address)
            return disassembly
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 获取特定函数的反汇编指令
    def handle_get_disassembly_function(self, args):
        try:
            name = args["name"]
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                start_address = function.start_ea
                end_address = function.end_ea

                disassembly = ""
                while start_address < end_address:
                    disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                    start_address = idc.next_head(start_address)
                return disassembly
            return f"No function found at address {name}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 反编译给定地址处的代码
    def handle_decompile_address(self, args):
        try:
            address = int(args["address"], 16)
            function = idaapi.get_func(address)
            if function:
                decompiled_code = idaapi.decompile(function)
                if decompiled_code:
                    return str(decompiled_code)
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 反编译由其名称指定的函数
    def handle_decompile_function(self, args):
        try:
            name = args["name"]
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                function = idaapi.get_func(function.start_ea)
                if function:
                    decompiled_code = idaapi.decompile(function)
                    if decompiled_code:
                        return str(decompiled_code)
                else:
                    self.PrintOutput(f"No function found at address {name}")
            return None
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 重命名反编译代码中特定地址处的局部变量
    def handle_rename_address(self, args):
        try:
            address = int(args["address"], 16)
            new_name = args["new_name"]
            old_name = args["old_name"]
            if new_name and old_name:
                ida_hexrays.rename_lvar(address, old_name, new_name)
                result = f"Renamed address {hex(address)} from '{old_name}' to '{new_name}'"
                self.PrintOutput(result)
                return result
            return None
        except Exception as e:
            return f"Error: {str(e)}"
    
    # 获取包含给定地址的函数的起始和结束地址
    def handle_get_function_start_end_address(self, args):
        try:
            address = int(args["address"], 16)
            function = idaapi.get_func(address)
            if function:
                start_address = hex(function.start_ea)
                end_address = hex(function.end_ea)
                result = {"start_address": start_address, "end_address": end_address}
                return result
            else:
                self.PrintOutput(f"No function found at address {hex(address)}")
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"

    def get_name_info(self):
        name_info = []
        for i in range(ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            name = ida_name.get_short_name(ea)
            name_info.append((name, hex(ea)))
        print("name_info:",name_info)
        return name_info

    def search_name(self, keyword):        
        search_results = []
        
        functions = self.get_name_info()
        for name, ea in functions:
            if keyword.lower() in name.lower():
                search_results.append((name, ea))
        
        return search_results
    
    # 搜索名称中包含指定关键字的函数
    def handle_get_addresses_of_name(self, args):
        try:
            name = args["name"]
            r = self.search_name(name)
            self.PrintOutput(f"Search results for '{name}': {r}")
            return r
        except Exception as e:
            return f"Error: {str(e)}"
    
    
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
    def handle_get_address_type(self, args):
        try:
            address = int(args["address"], 16)
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
    
    # 获取到指定地址的交叉引用    
    def handle_get_xrefs_to(self, args):
        try:
            address = int(args["address"], 16)
            xrefs = []
            for xref in idautils.XrefsTo(address, 0):
                xrefs.append((hex(xref.frm), self.get_type_ea(xref.frm), idautils.XrefTypeName(xref.type)))
            result = xrefs
            self.PrintOutput(f'Xrefs to {hex(address)}: {result}')
            return result
        except Exception as e:
            self.PrintOutput(f"handle_get_xrefs_to Error: {str(e)}")
            return f"Error: {str(e)}"
    
    # 获取从指定地址的交叉引用
    def handle_get_xrefs_from(self, args):
        try:
            address = int(args["address"], 16)
            xrefs = []
            for xref in idautils.XrefsFrom(address, 0):
                xrefs.append((hex(xref.to), self.get_type_ea(xref.to), idautils.XrefTypeName(xref.type)))
            result = xrefs
            self.PrintOutput(f'Xrefs from {hex(address)}: {result}')
            return result
        except Exception as e:
            self.PrintOutput(f"handle_get_xrefs_from Error: {str(e)}")
            return f"Error: {str(e)}"
    
    #  获取到指定地址处的函数内地址的交叉引用
    def handle_get_func_xrefs_to(self, args):
        try:
            address = int(args["address"], 16)
            if address != idc.BADADDR:
                xrefs = []
                for xref in idautils.XrefsTo(address, 0):
                    xrefs.append((hex(xref.frm), self.get_type_ea(xref.frm), idautils.XrefTypeName(xref.type)))
                result = xrefs
                self.PrintOutput(f'Xrefs to function at {hex(address)}: {result}')                
                return result
            self.PrintOutput(f"No function found at address {hex(address)}")
            return f"No function found at address {hex(address)}"
        except Exception as e:
            self.PrintOutput(f"handle_get_func_xrefs_to Error: {str(e)}")
            return f"Error: {str(e)}"
        
    def handle_print(self, args):
        message = args["message"]
        self.PrintOutput(message)
        return None
    
    # 在指定地址添加或修改可重复注释
    def handle_set_comment(self, args):
        try:
            address = int(args["address"], 16)
            comment = args["comment"]
            idc.set_cmt(address, comment, 1)
            result = f"Set comment at {hex(address)}: {comment}"
            self.PrintOutput(result)
            return None
        except Exception as e:
            return f"Error: {str(e)}"
            
    def handle_analyze_current_function_and_comment(self, args):
        from Binoculars.function.ExplainFunc import comment_callback 
        from Binoculars.config.config import default_model       
        
        try:
            widget = ida_kernwin.get_current_widget()  # 获取当前活动的 widget
            if ida_kernwin.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
                func_ea = idaapi.get_screen_ea()
                ida_hexrays.open_pseudocode(func_ea, 0)  # 打开或激活反编译窗口
                widget = ida_kernwin.get_current_widget()  # 重新获取 widget
            
            decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
            messages,systemprompt = {},""
            default_model.query_model_async(
            "你能解释一下下面的 C 函数的作用并为它建议一个更好的名称吗？不需要改进后的版本等其他信息！\n{decompiler_output}".format(decompiler_output=str(decompiler_output)),messages,systemprompt,
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=widget))
            return 1
        except Exception as e:
            return f"Error: {str(e)}"   
    
    # def handle_analyze_current_function_and_rename_variable(self,args):
        # from Binoculars.function.RenameFunc import rename_callback 
        # from Binoculars.config.config import default_model       
        
        # try:
            # widget = ida_kernwin.get_current_widget()  # 获取当前活动的 widget
            # decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
            # messages,systemprompt = {},""
            # default_model.query_model_async("分析以下C函数:\n{decompiler_output}\n建议更好的变量名称，用 JSON 数组回复，其中键是原始名称，值是建议的名称。不要解释任何内容，只打印 JSON 字典。".format(decompiler_output=str(decompiler_output)),messages,systemprompt,
            # functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=widget),
            # additional_model_options={"response_format": {"type": "json_object"}})
            # return 1
        # except Exception as e:
            # return f"Error: {str(e)}"  