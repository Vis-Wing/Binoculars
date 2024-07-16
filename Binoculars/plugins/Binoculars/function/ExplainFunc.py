import idaapi
import functools
import textwrap
import ida_hexrays
import idc
import re
import ida_kernwin
from Binoculars.config.config import default_model

class ExplainHandler(idaapi.action_handler_t):

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

        default_model.query_model_async(
            "你能解释一下下面的 C 函数的功能并为它建议一个更好的名称吗？不需要改进后的版本等其他信息！\n{decompiler_output}".format(decompiler_output=str(decompiler_output)),messages,systemprompt,
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=view))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        
        
def comment_callback(address, view, response):
  
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))
    comment = idc.get_func_cmt(address, 0)
    comment = re.sub(comment,comment,comment,flags=re.DOTALL)
    idc.set_func_cmt(address, f"{response.strip()}\n\n"f"{comment.strip()}", 0)
    
    if view:
        view.refresh_view(False)
    print("{model} 查询完成!".format(model=str(default_model)))