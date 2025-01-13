import re
import httpx
import openai
from Binoculars.models.base import BaseModel


class OPENAI(BaseModel):
    def __init__(self, model):
        super().__init__("OPENAI", model)
        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            http_client=httpx.Client(
                proxies=self.proxy,
            ) if self.proxy else None
        )

    def query_model(self, query, message_history, system_prompt, callback, additional_model_options=None):
        if additional_model_options is None:additional_model_options = {}
        messages = self.build_messages(query, message_history, system_prompt)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                **additional_model_options
            )
            response_content = response.choices[0].message.content
            
            self.execute_callback(callback, response_content)
        except openai.BadRequestError as e:
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            if m:
                print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")
            else:
                print(f"BadRequestError: General exception encountered while running the query: {str(e)}")
        except openai.AuthenticationError as e:
            print(f"AuthenticationError: {str(e)}")
        except openai.PermissionDeniedError as e:
            print(f"PermissionDeniedError: {str(e)}")
        except openai.NotFoundError as e:
            print(f"NotFoundError: {str(e)}")
        except openai.UnprocessableEntityError as e:
            print(f"UnprocessableEntityError: {str(e)}")
        except openai.RateLimitError as e:
            print(f"RateLimitError: {str(e)}")
        except openai.InternalServerError as e:
            print(f"InternalServerError: {str(e)}")
        except openai.APIConnectionError as e:
            print(f"APIConnectionError: {str(e)}")
        except Exception as e:
            print(f"General exception encountered while running the query: {str(e)}")


