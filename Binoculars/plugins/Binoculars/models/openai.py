import functools
import re
import threading
import httpx as _httpx
import ida_kernwin
import openai
from Binoculars.models.base import LanguageModel
from Binoculars.config.config import readconfig,writeconfig


class OPENAI(LanguageModel):
    def __init__(self, model):
        self.model = model
        self.api_key = readconfig("OPENAI", "API_KEY")
        if not self.api_key:
            print(_("Please edit the configuration file to insert your {api_provider} API key!")
                  .format(api_provider="OPENAI"))
            raise ValueError("No valid OPENAI API key found")
        self.proxy = readconfig("OPENAI", "OPENAI_PROXY")
        self.base_url = readconfig("OPENAI", "BASE_URL")
        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            http_client=_httpx.Client(
                proxies=self.proxy,
            ) if self.proxy else None
        )

    def __str__(self):
        return self.model

    def query_model(self, query, message_history, system_prompt, callback, additional_model_options=None):
        if additional_model_options is None:additional_model_options = {}
        messages = []
        if system_prompt:messages.append({"role": "system", "content": system_prompt})
        messages.extend(message_history)
        messages.append({"role": "user", "content": query})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                **additional_model_options
            )
            print("response:",response)
            ida_kernwin.execute_sync(functools.partial(callback, response=response.choices[0].message.content),ida_kernwin.MFF_WRITE)
        except openai.BadRequestError as e:
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            if m:
                print(_("Unfortunately, this function is too big to be analyzed with the model's current API limits."))
            else:
                print(_("General exception encountered while running the query: {error}").format(error=str(e)))
        except openai.OpenAIError as e:
            print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
        except Exception as e:
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))
            
    def query_model_async(self, query, message_history, system_prompt, callback, additional_model_options=None):
        if additional_model_options is None:additional_model_options = {}
        print(_("Request to {model} sent...").format(model=self.model))
        t = threading.Thread(target=self.query_model, args=[query, message_history, system_prompt, callback, additional_model_options])
        t.start()

