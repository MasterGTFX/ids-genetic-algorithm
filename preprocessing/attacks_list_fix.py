import pandas as pd



df = pd.read_csv("attack_list.csv")
df['Date'] = pd.to_datetime(df['Date'])
df['Start Time'] = pd.to_timedelta(df['Start Time'])
df['Duration'] = pd.to_timedelta(df['Duration'])
df['Attack Start'] = df['Date']+df['Start Time']
df['Attack End'] = df['Attack Start'] + df['Duration']
df.drop("Date", axis=1, inplace=True)
df.drop("Start Time", axis=1, inplace=True)
df.drop("Duration", axis=1, inplace=True)

remove_attacker = []
for index, row in df.iterrows():
    if "," in row['Attacker']:
        attack_default_row = row.copy()
        for attacker_ip in row['Attacker'].split(','):
            attack_default_row['Attacker'] = attacker_ip
            df = df.append(attack_default_row, ignore_index=True)
        remove_attacker.append(index)
df.drop(df.index[remove_attacker], inplace=True)
df.reset_index(drop=True, inplace=True)
remove_victim = []
for index, row in df.iterrows():
    if "," in row['Victim']:
        victim_default_row = row.copy()
        for victim_ip in row['Victim'].split(','):
            victim_default_row['Victim'] = victim_ip
            df = df.append(victim_default_row, ignore_index=True)
        remove_victim.append(index)

df.drop(df.index[remove_victim], inplace=True)
df.reset_index(drop=True, inplace=True)
df.to_csv("attack_list2.csv", index=False)
# print(df['Attacker'].tolist())
