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
global_default_model = None
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
        from Binoculars.config.config import default_model
        
        self.generate_plugin_select_menu(default_model)
        self.menu = ContextMenuHooks()
        self.menu.hook()
        
        return idaapi.PLUGIN_KEEP
    
    def generate_plugin_select_menu(self, default_model):
        global global_default_model
    
        global_default_model = default_model
        
        MODEL_CONFIGS = create_model_config()
        for model_config in MODEL_CONFIGS:
            idaapi.unregister_action(f"Binoculars:select_{model_config.model_class}_{model_config.name}")  
            
        for model_config in MODEL_CONFIGS:
            self.bind_model_switch_action(model_config, default_model)
    
    def bind_model_switch_action(self, model_config, default_model):
        from Binoculars.function.SwapModel import SwapModelHandler
     
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

class AssistantWidget(ida_kernwin.PluginForm, QtCore.QObject):
    def __init__(self):
        ida_kernwin.PluginForm.__init__(self)
        QtCore.QObject.__init__(self)
        self.icon = ida_kernwin.load_custom_icon("Binoculars/images/logo.ico")
        self.stop_flag = False
        self.message_history_flag = False
        self.default_model = global_default_model
    
    
    def change_default_model(self):
        global global_default_model
        self.default_model = global_default_model

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
        self.user_input = QtWidgets.QTextEdit()
        self.user_input.setFixedHeight(50)
        self.user_input.setStyleSheet("""
            QTextEdit {
                background-color: #F5F5F5;
                border: 1px solid #ccc;
                padding: 5px;
            }
        """)
        
        self.user_input.installEventFilter(self)
        input_layout.addWidget(self.user_input)
        
        # Send button
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
        
        # stop button
        stop_button = QtWidgets.QPushButton("Stop")
        stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336; /* 红色 */
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
            
            systemprompt = system_prompt if system_prompt_flag else ""
            systemprompt += command_prompt
            # system_prompt_flag = False
            
            query = f"{user_message}\nCurrent address: {hex(current_address)}"
            messages = message_history.copy() 
            self.default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived)
            
    
    def OnResponseReceived(self, response):
        global message_history, query
        from Binoculars.function.Handle import FuncHandle
        
        assistant_reply = response.strip().replace("```json\n", "").replace("```\n", "").strip()
        
        if self.message_history_flag:
            message_history.append({"role": "user", "content": query})
            message_history.append({"role": "assistant", "content": assistant_reply})    
            
        chat_history.append(f"<b>User:</b> {query}")
    
        try:
            assistant_reply = self.ParseResponse(assistant_reply)

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
                    # self.PrintOutput(f"Unknown command: {command_name}")
                    command_results[command_name] = None

            query = ""
            for command_name, result in command_results.items():
                if result is not None:
                    query += f"{command_name} result:\n{json.dumps(result)}\n\n"
                else:
                    # query += f"{command_name} result: None\n\n"
                    query += f"{command_name} result: An unknown command was used. This behavior is prohibited. Please use the command specified in the request.\n\n"
                    
            if len(query) > 0:
                systemprompt = system_prompt if system_prompt_flag else ""
                systemprompt += command_prompt
                messages = message_history.copy() 
                self.default_model.query_model_async(query, messages, systemprompt, self.OnResponseReceived)

        except Exception as e:
            traceback_details = traceback.format_exc()
            print(traceback_details)
            
            if not self.stop_flag:
                self.PrintOutput(f"Error parsing assistant response: {str(e)}")
                systemprompt = system_prompt if system_prompt_flag else ""
                systemprompt += command_prompt             
                messages = message_history.copy() 
                self.default_model.query_model_async(f"Error parsing response. please retry:\n {str(e)}", messages, systemprompt, self.OnResponseReceived)
            else:
                self.PrintOutput(f"Error parsing assistant response: {str(e)}")
            
    def sanitize_json(self, json_string):
        json_string = self.extract_json(json_string)
        json_string = re.sub(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', '', json_string)
        json_string = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_string)
        json_string = re.sub(r'"\s*\n\s*"', '""', json_string)
        json_string = re.sub(r'\s*\n\s*', '', json_string)
        
        return json_string   

    def extract_json(self, mixed_content):
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
            
    def ParseResponse(self, response):

        try:
            response = self.sanitize_json(response)
            if response:
                parsed_response = json.loads(response)
                return parsed_response
            else:
                raise Exception("The data you returned is not in the required JSON format. Please return the information in the required JSON format.")
        except json.JSONDecodeError as e:
            raise Exception(str(e) + "error occurred. suggestion: Return only the required data in JSON format. No additional explanations or information outside of the JSON format should be included.")
        except Exception as e:
            raise e
            
    def PrintOutput(self, output_str):
        self.chat_record.append(f"<b>System Message:</b> {output_str}")
        
        
