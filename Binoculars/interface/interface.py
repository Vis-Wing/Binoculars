import json
import ida_kernwin
import ida_name
import ida_ida
import idc
import idaapi
import re
import traceback
import ida_idaapi
from PyQt5 import QtWidgets, QtCore, QtGui
from Binoculars.config.config import readpromat
from collections import namedtuple
from Binoculars.function.Handle import FuncHandle
import inspect
import threading
import functools
import random
import string

chat_history = []
message_history = []
query = ""
global_default_model = None
system_prompt_flag = True
system_prompt = readpromat("prompt_base")
command_prompt = readpromat("prompt_command")
command_prompt += str(FuncHandle.get_ai_prompts("openai"))


def create_model_config():
    from Binoculars.config.config import get_model_list
    import ast
    MODEL_CONFIGS = []
    ModelConfig = namedtuple("ModelConfig", ["name", "model_class", "context_path"])
    model_map = get_model_list()
    for modelclass,modeltypes in model_map.items():
        for modeltype in modeltypes:
            MODEL_CONFIGS.append(ModelConfig(modeltype, modelclass ,f"{'SwapModel'}/{modelclass}/"))
    return MODEL_CONFIGS
    
class ContextMenuHooks(idaapi.UI_Hooks):
    def __init__(self, owner):
        super(ContextMenuHooks, self).__init__()
        self.owner = owner

    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            MODEL_CONFIGS = create_model_config()
            for model_config in MODEL_CONFIGS:
                menu_path = "Binoculars/" + model_config.context_path
                model_name = model_config.name

                if model_name in self.owner.model_action_map:
                    action_name = self.owner.model_action_map[model_name]["action_name"]
                    idaapi.attach_action_to_popup(form, popup, action_name, menu_path)
 

class IDAAssistant(ida_idaapi.plugin_t):
    global message_history,chat_history
    global query
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Binoculars"
    help = "Provides an AI assistant for reverse engineering tasks"
    wanted_name = "Binoculars"
    wanted_hotkey = "Alt-Q"
    model_action_map = {}

    def __init__(self):
        super(IDAAssistant, self).__init__()
        

    def init(self):
        from Binoculars.config.config import default_model
        
        self.generate_plugin_select_menu(default_model)
        self.menu = ContextMenuHooks(self)
        self.menu.hook()
        
        return idaapi.PLUGIN_KEEP
    
    
    def detach_actions(self):
        for model_name, action_info in self.model_action_map.items():
            action_name = action_info["action_name"]
            menu_path = action_info["menu_path"]
            
            ida_kernwin.execute_sync(functools.partial(idaapi.unregister_action, action_name), ida_kernwin.MFF_FAST)
            ida_kernwin.execute_sync(functools.partial(idaapi.detach_action_from_menu, menu_path, action_name), ida_kernwin.MFF_FAST)
        
        self.model_action_map.clear()
    
    def generate_plugin_select_menu(self, default_model):
        global global_default_model
        global_default_model = default_model

        def do_generate_model_select_menu():
            self.detach_actions()

            MODEL_CONFIGS = create_model_config()
            for model_config in MODEL_CONFIGS:
                menu_path = "Binoculars/" + model_config.context_path
                self.bind_model_switch_action(menu_path, model_config, default_model)

        threading.Thread(target=do_generate_model_select_menu).start()

        
    def bind_model_switch_action(self, menu_path, model_config, default_model):
        from Binoculars.function.SwapModel import SwapModelHandler


        unique_id = ''.join(random.choices(string.ascii_lowercase, k=7))
        action_name = f"Binoculars:select_{model_config.model_class}_{model_config.name}_{unique_id}"

        self.model_action_map[model_config.name] = {
            "action_name": action_name,
            "menu_path": menu_path
        }

        action = idaapi.action_desc_t(
            action_name,
            model_config.name,
            SwapModelHandler(model_config.model_class, model_config.name, self),
            "",
            "",
            208 if str(default_model) == model_config.name else 0
        )

        ida_kernwin.execute_sync(functools.partial(idaapi.register_action, action), ida_kernwin.MFF_FAST)
        ida_kernwin.execute_sync(
            functools.partial(idaapi.attach_action_to_menu, menu_path, action_name, idaapi.SETMENU_APP),
            ida_kernwin.MFF_FAST
        )


    def run(self, arg):
        self.assistant_window = AssistantWidget()
        self.assistant_window.Show("Binoculars")

    def term(self):
        if self.menu:
            self.menu.unhook()
        return

    def add_assistant_message(self, message):
        chat_history.append(f"<b>Assistant:</b> {message}") 

class AssistantWidget(ida_kernwin.PluginForm, QtCore.QObject):
    def __init__(self):
        from Binoculars.config.config import get_current_language
        ida_kernwin.PluginForm.__init__(self)
        QtCore.QObject.__init__(self)
        self.icon = ida_kernwin.load_custom_icon("Binoculars/images/logo.ico")
        self.stop_flag = False
        self.message_history_flag = True
        self.default_model = global_default_model      
        self.current_language = get_current_language()
        self.error_count = 0
        self.error_retry = 3
    
    def PrintOutput(self, output_str):
        self.chat_record.append(f"<b>System Message:</b> {output_str}")
    
    def change_default_model(self):
        global global_default_model
        self.default_model = global_default_model

    def OnCreate(self, form):
        # from Binoculars.function.Handle import FuncHandle
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        self.assistant = IDAAssistant()
        self.command_results = []
        self.func_handle = FuncHandle(self)
              

    def PopulateForm(self):
        from Binoculars.function.ExplainFunc import ExplainHandler 
        from Binoculars.function.RenameFunc import RenameHandler 
        # from Binoculars.function.GoParseFunc import ParseGoHandler 
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        self.view = ida_kernwin.get_current_viewer()
        self.output_window = ida_kernwin.find_widget("Output window")

        self.chat_record = QtWidgets.QTextEdit()
        self.chat_record.setReadOnly(True)
        self.chat_record.setStyleSheet("""
            QTextEdit {
                background-color: #F5F5F5;
                border: 1px solid #ddd;
                padding: 5px;
                font-family: monospace;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.chat_record)

        input_layout = QtWidgets.QHBoxLayout()
        self.user_input = QtWidgets.QTextEdit()
        self.user_input.setFixedHeight(50)
        self.user_input.setStyleSheet("""
            QTextEdit {
                background-color: #F5F5F5;
                border: 1px solid #ccc;
                padding: 5px;
                border-radius: 5px;
            }
        """)
        
        self.user_input.installEventFilter(self)
        input_layout.addWidget(self.user_input)
        
        button_style = """
            QPushButton {
                background-color: #e0e0e0;
                border: 1px solid #ccc;
                color: black;
                padding: 8px 16px;
                text-align: center;
                font-size: 14px;
                margin: 4px 2px;
                opacity: 0.8;
                transition: 0.3s;
                border-radius: 5px;
            }
            QPushButton:hover {opacity: 1}
            QPushButton:pressed { background-color: #c0c0c0; }
        """

        send_button = QtWidgets.QPushButton("Send")
        send_button.setStyleSheet(button_style)
        send_button.clicked.connect(self.OnSendClicked)
        input_layout.addWidget(send_button)
        
        stop_button = QtWidgets.QPushButton("Stop")
        stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                border: 1px solid #ccc;
                color: white;
                padding: 8px 16px;
                text-align: center;
                font-size: 14px;
                margin: 4px 2px;
                opacity: 0.8;
                transition: 0.3s;
                border-radius: 5px;
            }
            QPushButton:hover {opacity: 1}
            QPushButton:pressed { background-color: #d32f2f; }
        """)
        stop_button.clicked.connect(self.OnStopClicked)
        input_layout.addWidget(stop_button)

        layout.addLayout(input_layout)

        shortcut_layout = QtWidgets.QHBoxLayout()
        shortcut_layout.setAlignment(QtCore.Qt.AlignLeft)
        shortcut_label = QtWidgets.QLabel("Shortcut:")
        shortcut_layout.addWidget(shortcut_label)

        for text, action_name in [
            ("Analyze the current function", "explain_action"),
            ("Rename the current function variable", "rename_action"),
            ("Parsing Golang file symbols", "parsego_action")
        ]:
            button = QtWidgets.QPushButton(text)
            button.setStyleSheet(button_style + """
                QPushButton::menu-indicator {
                    image: none;
                }
            """)
                        
            font_metrics = button.fontMetrics()
            text_width = font_metrics.boundingRect(text).width()
            padding_horizontal = button.style().pixelMetric(QtWidgets.QStyle.PM_ButtonMargin) * 2
            button_min_width = text_width + padding_horizontal
            button.setMinimumWidth(button_min_width)
            shortcut_layout.addWidget(button)
            
            if text == "Analyze the current function":
                handler = ExplainHandler(self.default_model)
                self.update_handler(action_name=action_name, text=text, handler=handler, button=button)
            elif text == "Rename the current function variable":
                handler = RenameHandler()
                self.update_handler(action_name=action_name, text=text, handler=handler, button=button)
            elif text == "Parsing Golang file symbols":  
                menu = QtWidgets.QMenu(button)
                for option_text in ["1.recreate pclntab", "2.function discovery and renaming", "3.string cast", "4.extract types"]:
                    action = menu.addAction(option_text)
                    unique_action_name = f"{action_name}_{option_text.replace(' ', '_').replace('.', '').replace(':', '')}"
                    action.triggered.connect(lambda checked, opt=option_text, act_name=unique_action_name, txt=text: self.menu_option_triggered(opt, act_name, txt, button))
                button.setMenu(menu)
                

        layout.addLayout(shortcut_layout)
        self.parent.setLayout(layout)
    
    def menu_option_triggered(self, option_text, action_name, text, button):
        self.update_handler(action_name=action_name, text=text, option_text=option_text, button=button)
                
        output_window = ida_kernwin.find_widget("Output window")
        if output_window:
            ida_kernwin.activate_widget(output_window, True)
        ida_kernwin.process_ui_action(action_name)
    
    def update_handler(self, action_name, text, handler=None, option_text=None, button=None):
        
        from Binoculars.function.GoParseFunc import ParseGoHandler
        if text == "Parsing Golang file symbols":
            handler = ParseGoHandler(option_text)
            
        action_desc = idaapi.action_desc_t(
            action_name,
            text,
            handler,
            "",
            f"", 
            199
        )
        idaapi.unregister_action(action_name)
        idaapi.register_action(action_desc)

        if button:
            button.clicked.connect(lambda _, name=action_name: ida_kernwin.process_ui_action(name))
    
    def eventFilter(self, source, event):
        if event.type() == QtCore.QEvent.KeyPress and source is self.user_input:
            if event.key() == QtCore.Qt.Key_Return and event.modifiers() == QtCore.Qt.ShiftModifier:
                cursor = self.user_input.textCursor()
                cursor.insertText("\n")
                return True
            elif event.key() == QtCore.Qt.Key_Return:
                self.OnSendClicked()
                return True
        return super().eventFilter(source, event)
        
    def OnStopClicked(self):
        self.stop_flag = True
        self.chat_record.append(f"<b>System Message:</b> AI execution stopped.")
        
    def OnSendClicked(self):
        self.change_default_model()
        global message_history,query,system_prompt_flag
        self.stop_flag = False

        user_message = self.user_input.toPlainText().strip()
        if user_message:
            self.chat_record.append(f"<b>User:</b> {user_message}")
            self.user_input.clear()
            current_address = idc.here()
            
            systemprompt = (system_prompt if system_prompt_flag else "") + command_prompt
            # system_prompt_flag = False
            
            query = f"{user_message}\n" + f"Current address: {hex(current_address)}\n" + f"Reply in {self.current_language}"
            messages = message_history.copy() 
            self.default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived)
            
    # 接受回复
    def OnResponseReceived(self, response):
        global message_history, query
        
        assistant_reply = response.strip().replace("```json\n", "").replace("```\n", "").strip()
        
        if self.message_history_flag:
            message_history.append({"role": "user", "content": query})
            message_history.append({"role": "assistant", "content": assistant_reply})# 
            if len(message_history) > 20:
                message_history = message_history[2:]    
            
        chat_history.append(f"<b>User:</b> {query}")
    
        try:
            assistant_reply = self.ParseResponse(assistant_reply)

            if assistant_reply is None:
                self.chat_record.append(f"<b>System Message:</b> Failed to parse Binoculars response.")
                return

            if not assistant_reply:
                self.chat_record.append(f"<b>System Message:</b> No response from Binoculars.")
                return
                
            parsed_data = assistant_reply["parsed"]
            remaining_text = assistant_reply["remaining"]

            self.chat_record.append(f"<b>Binoculars:</b> {parsed_data['thoughts']['speak']}")
            if remaining_text:
                self.chat_record.append(f"<b>Binoculars:</b> {remaining_text}")
            
            
            commands = parsed_data['command']
            command_results = {}
            for command in commands:
                command_name = command['name']
                if command_name == "do_nothing":
                    continue
                command_args = command['args'].copy()
                command_args["default_model"] = self.default_model    
                
                command_handler = getattr(self.func_handle, f"{command_name}", None)
                
                if command_handler:
                    sig = inspect.signature(command_handler)
                    valid_params = list(sig.parameters.keys())
                    filtered_args = {k: v for k, v in command_args.items() if k in valid_params}
                    command_handler_result = command_handler(**filtered_args)
                    if isinstance(command_handler_result, dict) and "result" in command_handler_result:
                        self.PrintOutput(f"Module execution results: {command_handler_result['result']}")
        
                    command_results[command_name] = command_handler_result
                else:
                    self.PrintOutput(f"Unknown command: {command_name}")
                    command_results[command_name] = None

            query = ""
            for command_name, result in command_results.items():
                if result is not None:
                    query += f"{command_name} result:\n" + f"{json.dumps(result)}\n" + f"Reply in {self.current_language}\n"
                else:
                    # query += f"{command_name} result: None\n\n"
                    query += f"{command_name} result: An unknown command was used. This behavior is prohibited. Please use the command specified in the request.\n" + f"Reply in {self.current_language}\n"
                    
            if len(query) > 0:
                systemprompt = (system_prompt if system_prompt_flag else "") + command_prompt  
                messages = message_history.copy() 
                self.default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived) 

            self.error_count = 0

        except Exception as e:
            traceback_details = traceback.format_exc()
            print(traceback_details) # 打印了错误
            
            self.error_count += 1
            
            if self.error_count < self.error_retry and not self.stop_flag:
                self.PrintOutput(f"Error parsing Binoculars response: {str(e)}")
                systemprompt = (system_prompt if system_prompt_flag else "") + command_prompt            
                messages = message_history.copy() 
                query = f"Error parsing response:{str(e)}\n" + "Please refer to the error message to modify your reply\n" + f"Reply in {self.current_language}\n"
                self.default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived)
            else:
                self.PrintOutput(f"Error parsing Binoculars response: {str(e)}")
                

            
    def ParseResponse(self, response):
        try:
            json_str, remaining_text = self.sanitize_json(response)
            if json_str:
                parsed_response = json.loads(json_str)
                return {
                    "parsed": parsed_response,
                    "remaining": remaining_text.strip()
                }
            else:
                raise Exception("JSON format required.")
        except json.JSONDecodeError as e:
            raise Exception(f"{str(e)}. Return ONLY valid JSON.")
        except Exception as e:
            raise e

    def sanitize_json(self, mixed_content):
        json_str, remaining = self.extract_json(mixed_content)

        if not json_str:
            return "", mixed_content

        valid_escapes = ['\\n', '\\r', '\\t', '\\b', '\\f', '\\"', '\\\\', '\\/', '\\u']
        
        placeholder_map = {}
        def placeholder_replacer(match):
            s = match.group(0)
            placeholder = f"__ESCAPE_{len(placeholder_map)}__"
            placeholder_map[placeholder] = s
            return placeholder

        temp_json = json_str
        for valid in valid_escapes:
            import re
            temp_json = re.sub(re.escape(valid), placeholder_replacer, temp_json)

        temp_json = re.sub(r'\\(?![\\"nrtbfu/])', r'\\\\', temp_json)  # 修复非法 \x → \\x

        for placeholder, original in placeholder_map.items():
            temp_json = temp_json.replace(placeholder, original)

        temp_json = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', temp_json)  # 清理控制字符

        temp_json = re.sub(r'"\s*\n\s*"', '""', temp_json)  # "内容"\n"更多" → "" 更安全
        temp_json = re.sub(r'\s*\n\s*', ' ', temp_json)      # 换行 → 空格

        return temp_json, remaining


    def extract_json(self, mixed_content):
        stack = []
        json_start = -1
        json_str = ""
        remaining = mixed_content
        
        for i, char in enumerate(mixed_content):
            if char == '{':
                if not stack:
                    json_start = i
                stack.append(i)
            elif char == '}':
                if stack:
                    start = stack.pop()
                    if not stack:
                        json_str = mixed_content[json_start:i+1]
                        remaining = mixed_content[i+1:].lstrip()
                        break
        return json_str, remaining