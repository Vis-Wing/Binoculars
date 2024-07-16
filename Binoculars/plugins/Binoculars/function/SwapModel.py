import idaapi

class SwapModelHandler(idaapi.action_handler_t):

    def __init__(self, new_model_class, new_model, plugin):
        self.new_model_class = new_model_class
        self.new_model = new_model
        self.plugin = plugin

    def activate(self, ctx):
        from Binoculars.models.base import get_model
        from Binoculars.config.config import default_model
        from Binoculars.config.config import writeconfig
        
        try:
            default_model = get_model({self.new_model_class:self.new_model})
        except ValueError as e:
            print(_("Couldn't change model to {model}: {error}").format(model=self.new_model, error=str(e)))
            return
        writeconfig("MODEL", "Default_Model", self.new_model)
        self.plugin.generate_plugin_select_menu()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS