import functools
import threading
import httpx
import json
import ida_kernwin

from Binoculars.config.config import readconfig
from Binoculars.models.base import LanguageModel


class GPT360(LanguageModel):
    def __init__(self, model):
        self.model = model
        self.api_key = readconfig("GPT360", "API_KEY")
        if not self.api_key:
            print("Please edit the configuration file to insert your {api_provider} API key!"
                  .format(api_provider="360"))
            raise ValueError("No valid 360 API key found")
        self.proxy = readconfig("GPT360", "360GPT_PROXY")
        self.base_url =readconfig("GPT360", "BASE_URL")
        self.headers = {'Authorization': self.api_key,'Content-Type': 'application/json'}

    def __str__(self):
        return self.model

    def query_model(self, query, message_history, system_prompt, callback, additional_model_options=None):
    
        if additional_model_options is None:additional_model_options = {}
        messages = []
        if system_prompt:messages.append({"role": "system", "content": system_prompt})
        messages.extend(message_history)
        messages.append({"role": "user", "content": query})
        payload = {
            "model": self.model,
            "messages": messages,
            **additional_model_options
        }
        # print("payload:",payload)
        try:
            response = httpx.post(self.base_url, headers=self.headers, data=json.dumps(payload), timeout=120.0)
            response.raise_for_status()
            
            ida_kernwin.execute_sync(functools.partial(callback, response=response.json()['choices'][0]['message']['content']),ida_kernwin.MFF_WRITE)
        except httpx.TimeoutException:
            print(("{model} request timed out.").format(model=self.model))
        except httpx.ConnectError:
            print(("{model} could not connect to the server.").format(model=self.model))
        except httpx.HTTPStatusError as e:
            print(("{model} received a bad response: {status_code}").format(model=self.model, status_code=e.response.status_code))
        except httpx.RequestError as e:
            print(("{model} request failed: {error}").format(model=self.model, error=str(e)))
        except Exception as e:
            print(("General exception encountered while running the query: {error}").format(error=str(e)))

    def query_model_async(self, query, message_history, system_prompt, callback, additional_model_options=None):
      
        if additional_model_options is None:additional_model_options = {}
        print(("Request to {model} sent...").format(model=self.model))
        t = threading.Thread(target=self.query_model, args=[query, message_history, system_prompt, callback, additional_model_options])
        t.start()

