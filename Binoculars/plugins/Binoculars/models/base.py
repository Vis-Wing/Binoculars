import abc

class LanguageModel(abc.ABC):
    @abc.abstractmethod
    def query_model_async(self, query, cb):
        pass
 
def get_model(model_dict_str):
    from Binoculars.config.config import readconfig
    import ast
    import importlib
    
    model_map = ast.literal_eval(readconfig("MODEL","model_map"))
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