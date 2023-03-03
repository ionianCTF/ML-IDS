#!/usr/bin/env python
# coding: utf-8

# ===========================================================================

import os
import sys
from datetime import datetime
import collections
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import pickle
from nfstream import NFStreamer, NFPlugin
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
import seaborn as sns

# Sys - Configuration
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')

# Pandas - Configuration
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.expand_frame_repr', False)
pd.set_option('max_colwidth', None)
pd.options.display.float_format = "{:,.2f}".format

# SELECTED FEATURES

# Dataset Feature Names
list1 = ['ACK Flag Count', 'Bwd IAT Max', 'Bwd IAT Mean', 'Bwd IAT Min', 'Bwd IAT Std', 'Bwd Packet Length Max', 'Bwd Packet Length Mean', 'Bwd Packet Length Min', 'Bwd Packet Length Std', 'CWE Flag Count', 'Destination Port', 'ECE Flag Count', 'FIN Flag Count', 'Flow Duration', 'Flow IAT Max', 'Flow IAT Mean', 'Flow IAT Min', 'Flow IAT Std', 'Fwd IAT Max', 'Fwd IAT Mean', 'Fwd IAT Min', 'Fwd IAT Std', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Min', 'Fwd Packet Length Std', 'Max Packet Length', 'Min Packet Length', 'PSH Flag Count', 'Packet Length Mean', 'Packet Length Std', 'RST Flag Count', 'SYN Flag Count', 'Total Backward Packets', 'Total Fwd Packets', 'Total Length of Bwd Packets', 'Total Length of Fwd Packets', 'URG Flag Count']

# NFStream Feature Names
list2 = ['bidirectional_ack_packets', 'dst2src_max_piat_ms', 'dst2src_mean_piat_ms', 'dst2src_min_piat_ms', 'dst2src_stddev_piat_ms', 'dst2src_max_ps', 'dst2src_mean_ps', 'dst2src_min_ps', 'dst2src_stddev_ps', 'bidirectional_cwr_packets', 'dst_port', 'bidirectional_ece_packets', 'bidirectional_fin_packets', 'bidirectional_duration_ms', 'bidirectional_max_piat_ms', 'bidirectional_mean_piat_ms', 'bidirectional_min_piat_ms', 'bidirectional_stddev_piat_ms', 'src2dst_max_piat_ms', 'src2dst_mean_piat_ms', 'src2dst_min_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_max_ps', 'src2dst_mean_ps', 'src2dst_min_ps', 'src2dst_stddev_ps', 'bidirectional_max_ps', 'bidirectional_min_ps', 'bidirectional_psh_packets', 'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_rst_packets', 'bidirectional_syn_packets', 'dst2src_packets', 'src2dst_packets', 'dst2src_bytes', 'src2dst_bytes', 'bidirectional_urg_packets']


class MyEvent:
    """Data Structure for the date an event took place"""

    def __init__(self, txt):
        self.dt = datetime.today()
        self.txt = txt

    def __str__(self):
        return self.dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + " " + self.txt + "\n"


if __name__ == "__main__":

    if len(sys.argv) != 3:
        exit('Please provide <NFStreamer-source> <ML-Model-File-Path>')
    else:
        nfstreamer_source = sys.argv[1]
        model_file_path = sys.argv[2]
        print(f"\n - NFStreamer-source: {nfstreamer_source}\n - ML-Model-File-Path: {model_file_path}\n")

        if not os.path.exists(model_file_path):
            exit('The given <ML-Model-File-Path> does not exist !')

    # Load Classifier from File
    print(f"Loading ML Model from File: '{model_file_path}' ...")
    clf = pickle.load(open(model_file_path, 'rb'))
    print(f"Loading ML Model successfully completed !\n")

    # Check if the given source is a File-Path
    if os.path.exists(nfstreamer_source):
        # OFFLINE MODE
        print(f"OFFLINE MODE: Process the content of PCAP File: '{nfstreamer_source}'\n")
        df = NFStreamer(source=nfstreamer_source, statistical_analysis=True).to_pandas()
        print(f"There are {len(df.index)} flow(s) in the given PCAP File.\n")
        # Select Data & Rename Columns
        dfs = df[list2]
        dfs.columns = list1
        X = dfs.to_numpy()
        # Open File in Append mode
        report_file_path = './' + "ML-output.txt"
        report = open(report_file_path, "a")
        # For each Flow Selected Data
        count = 0
        for i in range(X.shape[0]):
            # Prepare Data
            tmp_X = X[i].reshape(1, X.shape[1])
            # Use Classifer
            tmp_y_pred = clf.predict(tmp_X)
            count += tmp_y_pred
            # Write (i.e., Append) String to File
            # MORE FEATURES CAN BE STORED IN NEWER VERSIONS
            msg_str = str(tmp_y_pred) + ' ' + ",".join(str(a) for a in tmp_X.tolist())
            event_str = str(MyEvent(msg_str))
            report.write(event_str)
        # Close File
        report.close()
        print(f"Abnormal Flows Detected: {count}\n")
    else:
        # ONLINE MODE
        print(f"ONLINE MODE: Read Data from SOURCE: '{nfstreamer_source}'\n")
        # IN CASE OF A PROBLEM, CHECK USING THIS COMMAND (without statistical analysis) INSTEAD OF THE FOLLOWING ONE
        # online_streamer = NFStreamer(source=nfstreamer_source)
        online_streamer = NFStreamer(source=nfstreamer_source, statistical_analysis=True)
        print(f"NFStreamer successfully setup.\n")
        for flow in online_streamer:
            # Just Print Flow Data - ML MODEL NOT CURRENTLY BEING USED
            print(flow)
        # IN THE CURRENT VERSION - NO FILE IS BEING CREATED IN THE ONLINE MODE
        # WE JUST PRINT THE OUTPUT
