import pandas as pd
import json
import demjson
import numpy as np
# data = [ { 'IP' : 1, 'b' : 2, 'c' : 3, 'd' : 4, 'e' : 5 } ]
class parse(object):
    def __init__(self, filename):
        self.csv_column_list = ["IP", "Hostname", "Port", "Port Protocol", "CVSS", "Severity", "Solution Type",
                                "NVT Name",
                                "Summary", "Specific Result", "NVT OID", "CVEs", "Task ID", "Task Name", "Timestamp",
                                "Result ID", "Impact", "Solution", "Affected Software/OS", "Vulnerability Insight",
                                "Vulnerability Detection Method", "Product Detection Result", "BIDs", "CERTs",
                                "Other References"]
        self.json_file = filename + ".json"
        self.filename = "./report/json/"+filename + ".csv"
        self.read_csv()

    def read_csv(self):
        data = pd.read_csv(self.filename)
        json_line = {}
        column_num = data.shape[0]
        raw_num = data.shape[1]
        with open(self.json_file, "w") as f:
            for i in range(column_num):
                for j in range(raw_num):
                    json_line[self.csv_column_list[j]] = data.loc[i][j]
                f.write(json.dumps(json_line, indent=4, cls=NpEncoder))
                print(json.dumps(json_line, indent=4, cls=NpEncoder))
        f.close()
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
