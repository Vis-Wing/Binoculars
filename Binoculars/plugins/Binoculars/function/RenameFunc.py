import idaapi
import functools
import ida_hexrays
import idc
import re
from Binoculars.config.config import default_model
import json
import ida_kernwin

class RenameHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        widget = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
            func_ea = idaapi.get_screen_ea()
            ida_hexrays.open_pseudocode(func_ea, 0)  # 打开或激活反编译窗口
            widget = ida_kernwin.get_current_widget()  # 重新获取 widget
        
        view = ida_hexrays.get_widget_vdui(widget)
        if view is None:
            idaapi.warning("Failed to get the pseudocode view.")
            return 1
    
        messages,systemprompt = {},""
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        default_model.query_model_async("分析以下C函数:\n{decompiler_output}\n建议更好的变量名称，用 JSON 数组回复，其中键是原始名称，值是建议的名称。不要解释任何内容，只打印 JSON 字典。".format(decompiler_output=str(decompiler_output)),messages,systemprompt,
            functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=view),
            additional_model_options={"response_format": {"type": "json_object"}})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        
def rename_callback(address, view, response, retries=0):
    names = json.loads(response)
    if type(names) == list:
        result = {}
        for name in names:
            result.update(name)
        names = result

    function_addr = idaapi.get_func(address).start_ea
    

    replaced = []
    for n in names:
        if idaapi.IDA_SDK_VERSION < 760:
            lvars = {lvar.name: lvar for lvar in view.cfunc.lvars}
            if n in lvars:
                if view.rename_lvar(lvars[n], names[n], True):
                    replaced.append(n)
        else:
            if ida_hexrays.rename_lvar(function_addr, n, names[n]):
                replaced.append(n)

    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    if view:
        view.refresh_view(True)
    print("{model} 查询完成! {replaced} 变量重命名.".format(model=str(default_model),
                                                                              replaced=len(replaced)))