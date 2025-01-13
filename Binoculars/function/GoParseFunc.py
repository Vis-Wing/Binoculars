import idaapi
import ida_kernwin
import threading
from Binoculars.function.GoParse.recreate_pclntab import main1 
from Binoculars.function.GoParse.function_discovery_and_renaming import main2 
from Binoculars.function.GoParse.string_cast import main4
from Binoculars.function.GoParse.extract_types import main5
from PyQt5 import QtWidgets

class ParseGoHandler(idaapi.action_handler_t):
    
    def __init__(self, option):
        idaapi.action_handler_t.__init__(self)
        self.option = option
        
    def activate(self, ctx):
        result = QtWidgets.QMessageBox.question(
            None,
            "Confirm Execution",
            "The script is about to run. Do you want to continue?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )
        if result == QtWidgets.QMessageBox.Yes:
            running_dialog = QtWidgets.QMessageBox(
                QtWidgets.QMessageBox.Information,
                "Running",
                "Operation is running, please wait...",
                QtWidgets.QMessageBox.Ok
            )
            running_dialog.setStandardButtons(QtWidgets.QMessageBox.Close)

            running_dialog.show()

            QtWidgets.QApplication.processEvents()

            try:
                if "1." in self.option:
                    main1()
                elif "2." in self.option:
                    main2()
                elif "3." in self.option:
                    main4()
                elif "4." in self.option:
                    main5()
            finally:
                running_dialog.close()
        else:
            print("[info] Operation was canceled by the user.")
        return 1  

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        