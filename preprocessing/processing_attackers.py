import pandas as pd
import datetime as dt
import numpy as np
import time
df = pd.read_csv("dataset1_fix.csv", low_memory=False, header=0)

print(df.dtypes)
n
attacks_df = pd.read_csv("attack_list2.csv", low_memory=False, header=0)
start = time.time()
for index, row in attacks_df.iterrows():
    print("{:.2f}%, {:.2f}s total".format(index*100/len(attacks_df), time.time()-start))
    ports_attacker = []
    ports_victim = []
    if 'nan' not in str(row['Ports Attacker']):
        ports_attacker = str(row['Ports Attacker']).split(",")
    if 'nan' not in str(row['Ports Victim']):
        ports_victim = str(row['Ports Victim']).split(",")
    if len(ports_attacker) > 5 or len(ports_victim) > 5:
        m = (df['src'] == row['Attacker']) & (df['dst'] == row['Victim']) & (df['time'] >= row['Attack Start']) & (
                    df['time'] <= row['Attack End'])
        df.loc[m, ['is_attack', 'attack_type', 'attack_name', 'attack_id']] = [1, row['Category'], row['Name'], row['ID']]
        continue
    if ports_attacker:
        for port in ports_attacker:
            if port == '':
                continue
            if port != 'i':
                m = (df['src'] == row['Attacker']) & (df['dst'] == row['Victim']) & (df['time'] >= row['Attack Start']) & (df['time'] <= row['Attack End']) & (df['sport'] == float(port))
                df.loc[m, ['is_attack', 'attack_type', 'attack_name', 'attack_id']] = [1, row['Category'], row['Name'], row['ID']]
            else:
                m = (df['src'] == row['Attacker']) & (df['dst'] == row['Victim']) & (df['time'] >= row['Attack Start']) & (df['time'] <= row['Attack End']) & (~df['proto'].isin([17.0, 6.0]))
                df.loc[m, ['is_attack', 'attack_type', 'attack_name', 'attack_id']] = [1, row['Category'], row['Name'], row['ID']]

    if ports_victim:
        for port in ports_victim:
            if port == '':
                continue
            if port != 'i':
                m = (df['src'] == row['Attacker']) & (df['dst'] == row['Victim']) & (df['time'] >= row['Attack Start']) & (df['time'] <= row['Attack End']) & (df['dport'] == float(port))
                df.loc[m, ['is_attack', 'attack_type', 'attack_name', 'attack_id']] = [1, row['Category'], row['Name'], row['ID']]
            else:
                m = (df['src'] == row['Attacker']) & (df['dst'] == row['Victim']) & (df['time'] >= row['Attack Start']) & (df['time'] <= row['Attack End']) & (~df['proto'].isin([17, 6]))
                df.loc[m, ['is_attack', 'attack_type', 'attack_name', 'attack_id']] = [1, row['Category'], row['Name'], row['ID']]
    if not ports_attacker and not ports_victim:
        m = (df['src'] == row['Attacker']) & (df['dst'] == row['Victim']) & (df['time'] >= row['Attack Start']) & (
                    df['time'] <= row['Attack End'])
        df.loc[m, ['is_attack', 'attack_type', 'attack_name', 'attack_id']] = [1, row['Category'], row['Name'], row['ID']]


df['sport'] = df['sport'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['dport'] = df['dport'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['ttl'] = df['ttl'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['len'] = df['len'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df.to_csv(f'dataset1_fix2.csv', index=False)
