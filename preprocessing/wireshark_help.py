import pandas as pd
df = pd.read_csv("attack_list.csv")
print(df)
last_id = '41'
wireshark = ''
for index,row in df.iterrows():

    if last_id == str(row['ID'])[:2]:
        if "," in row['Attacker'] or "," in row['Victim']:
            attackers = str(row['Attacker']).split(",")
            victims = str(row['Victim']).split(",")
            if len(victims) >10:
                for attacker in attackers:
                    wireshark += '|| (ip.src == {}) '.format(attacker)
                continue
            if len(attackers) >10:
                for victim in victims:
                    wireshark += '|| (ip.dst == {}) '.format(victim)
                continue
            for attacker in attackers:
                for victim in victims:
                    wireshark += '|| (ip.src == {} && ip.dst == {}) '.format(attacker, victim)
        else:
            wireshark += '|| (ip.src == {} && ip.dst == {}) '.format(row['Attacker'], row['Victim'])
    else:
        print("Linijka:", last_id)
        print(wireshark)
        if "," in row['Attacker'] or "," in row['Victim']:
            attackers = str(row['Attacker']).split(",")
            victims = str(row['Attacker']).split(",")
            for attacker in attackers:
                for victim in victims:
                    wireshark += '|| (ip.src == {} && ip.dst == {}) '.format(attacker, victim)
        else:
            wireshark = '|| (ip.src == {} && ip.dst == {}) '.format(row['Attacker'], row['Victim'])
        last_id = str(row['ID'])[:2]

print(last_id)
print(wireshark)
