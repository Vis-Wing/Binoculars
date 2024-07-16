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

chat_history = []
message_history = []
query = ""
system_prompt_flag = True
system_prompt = readpromat("prompt_base")
command_prompt = readpromat("prompt_command")


def create_model_config():
    from Binoculars.config.config import readconfig
    import ast
    MODEL_CONFIGS = []
    ModelConfig = namedtuple("ModelConfig", ["name", "model_class", "context_path"])
    model_map = ast.literal_eval(readconfig("MODEL","model_map"))
    for modelclass,modeltypes in model_map.items():
        for modeltype in modeltypes:
            MODEL_CONFIGS.append(ModelConfig(modeltype, modelclass ,f"{'SwapModel'}/{modelclass}/"))
    return MODEL_CONFIGS
    
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        MODEL_CONFIGS = create_model_config()
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            for model_config in MODEL_CONFIGS:
                action_name = f"Binoculars:select_{model_config.model_class}_{model_config.name}"
                idaapi.attach_action_to_popup(form, popup, action_name, "Binoculars/"+model_config.context_path) 

class IDAAssistant(ida_idaapi.plugin_t):
    global message_history,chat_history
    global query
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Binoculars"
    help = "Provides an AI assistant for reverse engineering tasks"
    wanted_name = "Binoculars"
    wanted_hotkey = "Alt-Q"

    def __init__(self):
        super(IDAAssistant, self).__init__()

    def init(self):
        
        self.generate_plugin_select_menu()
        self.menu = ContextMenuHooks()
        self.menu.hook()
        
        return idaapi.PLUGIN_KEEP
    
    def generate_plugin_select_menu(self):
        MODEL_CONFIGS = create_model_config()
        for model_config in MODEL_CONFIGS:
            idaapi.unregister_action(f"Binoculars:select_{model_config.model_class}_{model_config.name}")  
            
        for model_config in MODEL_CONFIGS:
            self.bind_model_switch_action(model_config)
    
    def bind_model_switch_action(self, model_config):
        from Binoculars.function.SwapModel import SwapModelHandler
        from Binoculars.config.config import default_model
        action_name = f"Binoculars:select_{model_config.model_class}_{model_config.name}"
        action = idaapi.action_desc_t(action_name,
                                      model_config.name,
                                      None if str(default_model) == model_config.name
                                      else SwapModelHandler(model_config.model_class, model_config.name, self),
                                      "",
                                      "",
                                      208 if str(default_model) == model_config.name else 0)
        idaapi.register_action(action)

    def run(self, arg):
        self.assistant_window = AssistantWidget()
        self.assistant_window.Show("Binoculars")

    def term(self):
        if self.menu:
            self.menu.unhook()
        return

    def add_assistant_message(self, message):
        chat_history.append(f"<b>Assistant:</b> {message}") 

class AssistantWidget(ida_kernwin.PluginForm):
    def __init__(self):
            ida_kernwin.PluginForm.__init__(self)
            self.icon = ida_kernwin.load_custom_icon("Binoculars/images/logo.ico")

    def OnCreate(self, form):
        from Binoculars.function.Handle import FuncHandle
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        self.assistant = IDAAssistant()
        self.command_results = []
        self.func_handle = FuncHandle(self)
               
    def PopulateForm(self):
        from Binoculars.function.ExplainFunc import ExplainHandler 
        from Binoculars.function.RenameFunc import RenameHandler 
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
                border: 1px solid #ddd;     /* 浅灰色边框 */
                padding: 5px;
                font-family: monospace;     /* 等宽字体 */
            }
        """)
        layout.addWidget(self.chat_record)


        input_layout = QtWidgets.QHBoxLayout()
        self.user_input = QtWidgets.QLineEdit()
        self.user_input.setStyleSheet("""
            QLineEdit {
                background-color: #F5F5F5;
                border: 1px solid #ccc;
                padding: 5px;
            }
        """)
        input_layout.addWidget(self.user_input)
        self.user_input.returnPressed.connect(self.OnSendClicked)

        send_button = QtWidgets.QPushButton("Send")
        send_button.setStyleSheet("""
            QPushButton {
                background-color: #e0e0e0; /* 浅灰色 */
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
        """)
        send_button.clicked.connect(self.OnSendClicked)
        input_layout.addWidget(send_button)

        layout.addLayout(input_layout)

        shortcut_layout = QtWidgets.QHBoxLayout()
        shortcut_layout.setAlignment(QtCore.Qt.AlignLeft)
        shortcut_label = QtWidgets.QLabel("shortcut:")
        shortcut_layout.addWidget(shortcut_label)
 
        for text, action_name in [
            ("Analyze the current function", "explain_action"),
            ("Rename the current function variable", "rename_action")
        ]:
            button = QtWidgets.QPushButton(text)
            button.setStyleSheet("""
            QPushButton {
                background-color: #e0e0e0; 
                border: 1px solid #ccc;
                color: black;
                padding: 6px 16px;
                text-align: center;
                font-size: 14px;
                margin: 4px 2px;
                opacity: 0.8;
                transition: 0.3s;
                border-radius: 5px; /* 添加圆角 */
            }
            QPushButton:hover {opacity: 1}
            QPushButton:pressed { background-color: #c0c0c0; }
        """)
            
            font_metrics = button.fontMetrics()
            text_width = font_metrics.boundingRect(text).width()
            padding_horizontal = button.style().pixelMetric(QtWidgets.QStyle.PM_ButtonMargin) * 2
            button_min_width = text_width + padding_horizontal
            button.setMinimumWidth(button_min_width)
            shortcut_layout.addWidget(button)
            
            action_desc = idaapi.action_desc_t(
                action_name,
                text,
                ExplainHandler() if text == "Analyze the current function" else RenameHandler(),
                "",
                f"", 
                199
            )
            idaapi.register_action(action_desc)
            button.clicked.connect(lambda _, name=action_name: ida_kernwin.process_ui_action(name))

        layout.addLayout(shortcut_layout)
        self.parent.setLayout(layout)
    
    def OnSendClicked(self):
        global message_history,query,system_prompt_flag
        from Binoculars.config.config import default_model

        user_message = self.user_input.text().strip()
        if user_message:
            self.chat_record.append(f"<b>User:</b> {user_message}")
            self.user_input.clear()
            current_address = idc.here()
            
            systemprompt = system_prompt if system_prompt_flag else ""
            systemprompt += command_prompt
            # system_prompt_flag = False
            
            query = f"{user_message}\nCurrent address: {hex(current_address)}"
            messages = message_history.copy() 

            default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived)
            
    
    def OnResponseReceived(self, response):
        global message_history, query
        from Binoculars.config.config import default_model
        from Binoculars.function.Handle import FuncHandle
        
        assistant_reply = response.strip().replace("```json\n", "").replace("```\n", "").strip()
        
        message_history.append({"role": "user", "content": query})
        message_history.append({"role": "assistant", "content": assistant_reply})            
        chat_history.append(f"<b>User:</b> {query}")
    
        try:
            assistant_reply = self.ParseResponse(assistant_reply)
            # print("assistant_reply:",assistant_reply)

            if assistant_reply is None:
                self.chat_record.append(f"<b>System Message:</b> Failed to parse assistant response.")
                return

            if not assistant_reply:
                self.chat_record.append(f"<b>System Message:</b> No response from assistant.")
                return
                
            self.chat_record.append(f"<b>Assistant speak:</b> {assistant_reply['thoughts']['speak']}")

            commands = assistant_reply['command']
            command_results = {}
            for command in commands:
                command_name = command['name']
                if command_name == "do_nothing":
                    continue
                command_args = command['args']
                command_handler = getattr(self.func_handle, f"handle_{command_name}", None)
                if command_handler:          
                    command_results[command_name] = command_handler(command_args)
                else:
                    self.PrintOutput(f"Unknown command: {command_name}")
                    command_results[command_name] = None

            query = ""
            for command_name, result in command_results.items():
                if result is not None:
                    query += f"{command_name} result:\n{json.dumps(result)}\n\n"
                else:
                    query += f"{command_name} result: None\n\n"
                    
            if len(query) > 0:
                systemprompt = system_prompt if system_prompt_flag else ""
                systemprompt += command_prompt
                messages = message_history.copy() 
                default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived)

        except Exception as e:
            systemprompt = system_prompt if system_prompt_flag else ""
            systemprompt += command_prompt
            traceback_details = traceback.format_exc()
            print(traceback_details)
            self.PrintOutput(f"Error parsing assistant response: {str(e)}")
            messages = message_history.copy() 
            default_model.query_model_async(f"Error parsing response. please retry:\n {str(e)}", messages, systemprompt, self.OnResponseReceived)
            
    def sanitize_json(self, json_string):
        json_string = re.sub(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', '', json_string)
        json_string = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_string)
        json_string = re.sub(r'"\s*\n\s*"', '""', json_string)
        json_string = re.sub(r'\s*\n\s*', '', json_string)
        
        return json_string    
            
    def ParseResponse(self, response):
        try:
            response = self.sanitize_json(response)
            parsed_response = json.loads(response)
            return parsed_response
        except json.JSONDecodeError as e:
            traceback_details = traceback.format_exc()
            print(traceback_details)
            raise e
        except Exception as e:
            print(str(e))
            traceback_details = traceback.format_exc()
            print(traceback_details)
            raise e
            
    def PrintOutput(self, output_str):
        self.chat_record.append(f"<b>System Message:</b> {output_str}")
        
        
