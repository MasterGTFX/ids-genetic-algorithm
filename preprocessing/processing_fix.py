import pandas as pd
import datetime as dt
import numpy as np

df = pd.read_csv("dataset1.csv", low_memory=False, header=0)
df['time'] = pd.to_datetime(df['time'], unit='s') - dt.timedelta(hours=5)
df['sport'] = df['sport'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['dport'] = df['dport'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['ttl'] = df['ttl'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['len'] = df['len'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['is_attack'] = 0
df['attack_type'] = np.nan
df['attack_name'] = np.nan
df['attack_id'] = np.nan




print(df.columns)


df.to_csv(f'dataset1_fix.csv',  index=False)
