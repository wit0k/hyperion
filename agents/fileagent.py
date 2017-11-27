from .core.agent import *
from .handlers.rtf import *

class fileagent(agent):

    def md5(fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    handler = {
        "rtf": rtf
    }

    def __init__(self, file, filetype):
        self.filetype = filetype
        self.filehash = self.md5(file)

        if file:
            self.file = file
            result = self.handler[self.filetype](self.file)

            if result.output:
                for item in result.output:
                    output_str = []

                    item["file_hash"] = self.filehash
                    for key in result.output_format:
                        try:
                            if isinstance(item[key], list):
                                output_str.append("; ".join(item[key]))
                            else:
                                output_str.append(str(item[key]))
                        except KeyError:
                            output_str.append("")

                    print(output_str, sep=",")



