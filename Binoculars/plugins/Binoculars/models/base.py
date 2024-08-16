import abc
import threading
import json
import ida_kernwin
import functools
import logging
from Binoculars.config.config import readconfig

class LanguageModel(abc.ABC):
    @abc.abstractmethod
    def query_model_async(self, query, cb):
        pass
 
def get_model(model_dict_str):
    from Binoculars.config.config import get_model_list
    import ast
    import importlib
    
    model_map = get_model_list()
    model_dict = ast.literal_eval(model_dict_str)
    model_class = list(model_dict.keys())[0]
    model_type = list(model_dict.values())[0]

    try:
        if model_type in model_map.get(model_class, []):
            module = importlib.import_module(f"Binoculars.models.{model_class.lower()}")
            model_class = getattr(module, model_class)
            return model_class(model_type)
        else:
            raise ValueError(f"Model '{model_type}' not found for provider '{model_class}'")
    except (ImportError, AttributeError, ValueError) as e:
        print(f"Error loading model: {e}")
        return None 
        
        

class BaseModel(LanguageModel):
    def __init__(self, provider, model):
        logging.getLogger("httpx").setLevel(logging.WARNING)
        self.provider = provider
        self.model = model
        self.base_url = readconfig(provider, "BASE_URL")
        self.api_key = readconfig(provider, "API_KEY")
        if not self.api_key:
            print(f"Please edit the configuration file to insert your {provider} API key!")
            raise ValueError(f"No valid {provider} API key found")
        self.proxy = readconfig(provider, f"{provider}_PROXY")
        

    def __str__(self):
        return self.model

    def build_messages(self, query, message_history, system_prompt):
        messages = []
        if system_prompt:messages.append({"role": "system", "content": system_prompt})
        messages.extend(message_history)
        messages.append({"role": "user", "content": query})
       
        return messages
    
    def execute_callback(self, callback, response_content):
        ida_kernwin.execute_sync(functools.partial(callback, response=response_content), ida_kernwin.MFF_WRITE)


    def query_model(self, query, message_history, system_prompt, callback, additional_model_options=None):
        raise NotImplementedError("Subclasses should implement this method")

    def query_model_async(self, query, message_history, system_prompt, callback, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}
        print(f"Request to {self.model} sent...")
        t = threading.Thread(target=self.query_model, args=[query, message_history, system_prompt, callback, additional_model_options])
        t.start()