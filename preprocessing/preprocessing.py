import pandas as pd
import numpy as np
import binascii
from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
import datetime as dt
import os
import time
# Collect field names from IP/TCP/UDP (These will be columns in DF)
ip_fields = [field.name for field in IP().fields_desc]
tcp_fields = [field.name for field in TCP().fields_desc]
udp_fields = [field.name for field in UDP().fields_desc]
print(ip_fields)
print(tcp_fields)
print(udp_fields)
# TBD len != len of ip header
# TBD flags, change this field
dataframe_IP_fields = ['src', 'dst', 'ttl', 'proto', 'flags',  'len']
time_field = ['time']
dataframe_L4_fields = ['sport', 'dport']
dataframe_fields = dataframe_IP_fields+time_field+dataframe_L4_fields



tcpdump_files = os.listdir("data")
for file in tcpdump_files:
    start_time = time.time()
    df = pd.DataFrame(columns=dataframe_fields)
    print(f"File: {file}... ", end="")
    pcap = rdpcap(f'data/{file}')
    df = pd.DataFrame(columns=dataframe_fields)
    for packet in pcap[IP]:
        #print(f"{count}/{packets}")
        field_values = []
        layer_type = type(packet[IP].payload)
        for field in dataframe_IP_fields:
            field_values.append(packet[IP].fields[field])
        field_values.append(float(packet.time))
        for field in dataframe_L4_fields:
            if layer_type == TCP:
                field_values.append(packet[TCP].fields[field])
            elif layer_type == UDP:
                field_values.append(packet[UDP].fields[field])
            else:
                field_values.append(None)
        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)
    # Reset Index
    df = df.reset_index()
    # Drop old index column
    df = df.drop(columns="index")
    df.to_csv(f'dataset1.csv',  index=False,header=False, mode='a')
    print(" Done! time:{}".format(start_time-time.time()))
    #
    # print(df.head())
    # print(df.columns)
    # print(df.describe())