import pandas as pd
import matplotlib.pyplot as plt


df = pd.read_csv("dataset1_fix2.csv", low_memory=False, header=0)
my_labels = ['Normalny', "Atak"]
# df['is_attack'].value_counts().plot(kind='pie', title="Typ ruchu sieciowego",
#             fontsize=12,labels=my_labels, colors=['lightgreen', 'red'], autopct='%1.1f%%', figsize=(13,13)).yaxis.set_visible(False)

df.drop_duplicates(subset=['src', 'sport', 'dst', 'dport', 'proto', 'ttl', 'len', 'flags', 'attack_id'], inplace=True)
print(df.info())
# my_labels = ['Normalny', "Atak"]
# df['is_attack'].value_counts().plot(kind='pie', title="Typ ruchu sieciowego (po usunięciu duplikatów)",
#             fontsize=12,labels=my_labels, colors=['lightgreen', 'red'], autopct='%1.1f%%', figsize=(13,13)).yaxis.set_visible(False)

attacks = df[df['is_attack'] == 1]
normal = df[df['is_attack'] != 1].sample(n=240147)
frames = [normal, attacks]
df = pd.concat(frames)
print(df)
df['is_attack'].value_counts().plot(kind='pie', title="Typ ruchu sieciowego (po usunięciu duplikatów oraz redukcji danych)",
            fontsize=12,labels=my_labels, colors=['lightgreen', 'red'], autopct='%1.1f%%', figsize=(13,13)).yaxis.set_visible(False)
#df[df['is_attack']==1]['attack_type'].value_counts().plot(kind='bar',  figsize=(7, 6), rot=0)
#df['attack_type'].value_counts().plot(kind='bar',  figsize=(7, 6), rot=0)
plt.show()
print(len(df[df['is_attack']==1]), len(df), len(df[df['is_attack']==1])*100/len(df))

df['sport'] = df['sport'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['dport'] = df['dport'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['ttl'] = df['ttl'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df['len'] = df['len'].apply(lambda x: x if pd.isnull(x) else str(int(x)))
df.to_csv(f'dataset1_downsampled.csv', index=False)