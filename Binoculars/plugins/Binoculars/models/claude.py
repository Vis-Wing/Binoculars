import re
import httpx
import anthropic
from Binoculars.models.base import BaseModel


class CLAUDE(BaseModel):
    def __init__(self, model):
        super().__init__("CLAUDE", model)
        self.max_tokens= 1024
        self.client = anthropic.Anthropic(
            api_key= self.api_key,
            base_url=self.base_url,
            http_client=httpx.Client(
                proxies=self.proxy,
            ) if self.proxy else None
        )

    def query_model(self, query, message_history, system_prompt, callback, additional_model_options=None):
        if additional_model_options is None:additional_model_options = {}
        messages = self.build_messages(query, message_history, system_prompt)
        try:
            try:
                response = self.client.messages.create(
                    max_tokens = self.max_tokens,
                    model=self.model,
                    messages=messages,
                    **additional_model_options
                )
            except:
                response = self.client.completions.create(
                    max_tokens_to_sample = self.max_tokens,
                    model=self.model,
                    prompt=messages,
                    **additional_model_options
                )

            response_content = response.content[0].text.strip().replace("```json\n", "").replace("```\n", "").strip()
            
            self.execute_callback(callback, response_content)
        except anthropic.BadRequestError as e:
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            if m:
                print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")
            else:
                print(f"BadRequestError: General exception encountered while running the query: {str(e)}")
        except anthropic.AuthenticationError as e:
            print(f"AuthenticationError: {str(e)}")
        except anthropic.PermissionDeniedError as e:
            print(f"PermissionDeniedError: {str(e)}")
        except anthropic.NotFoundError as e:
            print(f"NotFoundError: {str(e)}")
        except anthropic.UnprocessableEntityError as e:
            print(f"UnprocessableEntityError: {str(e)}")
        except anthropic.RateLimitError as e:
            print(f"RateLimitError: {str(e)}")
        except anthropic.InternalServerError as e:
            print(f"InternalServerError: {str(e)}")
        except anthropic.APIConnectionError as e:
            print(f"APIConnectionError: {str(e)}")
        except Exception as e:
            print(f"General exception encountered while running the query: {str(e)}")


