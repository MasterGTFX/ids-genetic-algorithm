import pandas as pd
import matplotlib.pyplot as plt


df = pd.read_csv("dataset1_fix2.csv", low_memory=False, header=0)


print(df.info())
my_labels = ['Normalny', "Atak"]
df['is_attack'].value_counts().plot(kind='pie', title="Typ ruchu sieciowego",
            fontsize=12,labels=my_labels, colors=['lightgreen', 'red'], autopct='%1.1f%%', figsize=(13,13)).yaxis.set_visible(False)
#df[df['is_attack']==1]['attack_type'].value_counts().plot(kind='bar',  figsize=(7, 6), rot=0)
#df['attack_type'].value_counts().plot(kind='bar',  figsize=(7, 6), rot=0)
plt.show()
print(len(df[df['is_attack']==1]), len(df), len(df[df['is_attack']==1])*100/len(df))