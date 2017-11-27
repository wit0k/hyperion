from .core.agent import *
from .handlers.rtf import *

class fileagent(agent):

    handler = {
        "rtf": rtf
    }

    def __init__(self, file, filetype):
        self.filetype = filetype

        if file:
            self.file = file
            result = self.handler[self.filetype](self.file)

            if result.output:
                for item in result.output:
                    output_str = []
                    for key in result.output_format:
                        try:
                            if isinstance(item[key], list):
                                output_str.append("; ".join(item[key]))
                            else:
                                output_str.append(str(item[key]))
                        except KeyError:
                            output_str.append("")

                    print(output_str, sep=",")



