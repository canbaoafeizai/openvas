import pandas as pd
import json
import demjson
import numpy as np
import login
import os

json_path = login.json_path


class parse(object):
    def __init__(self, filename):
        self.csv_column_list = ["IP", "Hostname", "Port", "Port Protocol", "CVSS", "Severity", "Solution Type",
                                "NVT Name",
                                "Summary", "Specific Result", "NVT OID", "CVEs", "Task ID", "Task Name", "Timestamp",
                                "Result ID", "Impact", "Solution", "Affected Software/OS", "Vulnerability Insight",
                                "Vulnerability Detection Method", "Product Detection Result", "BIDs", "CERTs",
                                "Other References"]
        self.csv_name = filename + ".csv"
        self.json_file_name = filename + ".json"
        self.json_file_path = os.path.join(json_path, self.json_file_name)
        self.convert_csv_to_json()

    def convert_csv_to_json(self):
        data = pd.read_csv(login.csv_path+self.csv_name)
        json_line = {}
        column_num = data.shape[0]
        raw_num = data.shape[1]
        try:
            with open(self.json_file_path, "w") as f:
                for i in range(column_num):
                    for j in range(raw_num):
                        json_line[self.csv_column_list[j]] = data.loc[i][j]
                    f.write(json.dumps(json_line, indent=4, cls=NpEncoder))
            print("conver success,name={}".format(self.json_file_path))
            f.close()
        except:
            print("csv to json failed!")

class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return super(NpEncoder, self).default(obj)
