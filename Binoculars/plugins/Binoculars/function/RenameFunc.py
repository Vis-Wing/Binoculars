import idaapi
import functools
import ida_hexrays
import idc
import re
import json
import ida_kernwin
from Binoculars.config.config import get_current_model

class RenameHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        default_model = get_current_model()
        
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
        
        default_model.query_model_async("Analyze the following C function and suggest better variable names:\n{decompiler_output}\nRespond with a JSON object where the keys are the original names and the values are the suggested names. Do not interpret or add any additional information, just print the JSON object.".format(decompiler_output=str(decompiler_output)),messages,systemprompt,functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=view,default_model=default_model),additional_model_options={"response_format": {"type": "json_object"}})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        
        

        
def rename_callback(address, view, response, default_model, retries=0):
    response = sanitize_json(response)
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


def sanitize_json(mixed_content):
    json_string = extract_json(mixed_content)  
    json_string = re.sub(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', '', json_string)
    json_string = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_string)
    json_string = re.sub(r'"\s*\n\s*"', '""', json_string)
    json_string = re.sub(r'\s*\n\s*', '', json_string)
    
    return json_string   

def extract_json(mixed_content):
    json_str = ''
    stack = []
    slash = False

    for i, char in enumerate(mixed_content):
        if slash:
            slash = False
            continue

        if char == '{':
            stack.append(i)
        elif char == '}':
            if not stack:
                continue
            start = stack.pop()
            json_str = mixed_content[start:i + 1]
        elif char == '\\':
            slash = True

    return json_str