import httpx
import json
from Binoculars.models.base import BaseModel

        
        
class GPT360(BaseModel):
    def __init__(self, model):
        super().__init__("GPT360", model)
        self.headers = {'Authorization': self.api_key, 'Content-Type': 'application/json'}

    def query_model(self, query, message_history, system_prompt, callback, additional_model_options=None):
        if additional_model_options is None:additional_model_options = {}
        messages = self.build_messages(query, message_history, system_prompt)
        payload = {
            "model": self.model,
            "messages": messages,
            **additional_model_options
        }
        # print(messages)
        try:
            response = httpx.post(self.base_url, headers=self.headers, data=json.dumps(payload), timeout=120.0, proxies=self.proxy if self.proxy else None)
            response.raise_for_status()
            response_content = response.json()['choices'][0]['message']['content']
            
            self.execute_callback(callback, response_content)
            
        except httpx.TimeoutException:
            print(f"{self.model} request timed out.")
        except httpx.ConnectError:
            print(f"{self.model} could not connect to the server.")
        except httpx.HTTPStatusError as e:
            print(f"{self.model} received a bad response: {e.response.status_code}")
        except httpx.RequestError as e:
            print(f"{self.model} request failed: {str(e)}")
        except Exception as e:
            print(f"General exception encountered while running the query: {str(e)}")


