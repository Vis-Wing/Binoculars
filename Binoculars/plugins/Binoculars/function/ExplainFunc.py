import idaapi
import functools
import textwrap
import ida_hexrays
import idc
import re
import ida_kernwin
from Binoculars.config.config import get_current_model
from Binoculars.config.config import get_current_language


class ExplainHandler(idaapi.action_handler_t):

    def __init__(self, default_model):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        default_model = get_current_model()
        current_language = get_current_language()
    
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
            "Can you explain the purpose of the following C function and suggest a better name for it? No need for an improved version or other information! Please reply in {current_language}!\n{decompiler_output}".format(decompiler_output=str(decompiler_output),current_language=current_language),messages,systemprompt,functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=view, default_model=default_model))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        
        
def comment_callback(address, view, response, default_model):
  
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))
    comment = idc.get_func_cmt(address, 0)
    comment = re.sub(comment,comment,comment,flags=re.DOTALL)
    idc.set_func_cmt(address, f"{response.strip()}\n\n"f"{comment.strip()}", 0)
    
    if view:
        view.refresh_view(False)
    print("{model} 查询完成!".format(model=str(default_model)))