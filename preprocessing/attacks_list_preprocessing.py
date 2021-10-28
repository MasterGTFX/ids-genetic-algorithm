import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

columns = ['ID', 'Date', 'Name', 'Category', 'Start Time', 'Duration', 'Attacker', 'Victim', 'Ports Attacker',
           'Ports Victim']

attacks_df = pd.DataFrame(columns=columns)

with open('master_identifications.list.txt', 'r') as attacks_raw:
    for line in attacks_raw.readlines():
        if line.startswith("ID: "):
            ID = line.split("ID: ")[1].replace("\n", "").replace(" ", "")
        elif line.startswith("Date: "):
            Date = line.split("Date: ")[1].replace("\n", "").replace(" ", "")
        elif line.startswith("Name: "):
            Name = line.split("Name: ")[1].replace("\n", "").replace(" ", "")
        elif line.startswith("Category: "):
            Category = line.split("Category: ")[1].replace("\n", "").replace(" ", "")
        elif line.startswith("Start_Time: "):
            Start_Time = line.split("Start_Time: ")[1].replace("\n", "").replace(" ", "")
        elif line.startswith("Duration: "):
            Duration = line.split("Duration: ")[1].replace("\n", "").replace(" ", "")
        elif line.startswith("Attacker: "):
            if "," in line:
                attacker_ips = line.split("Attacker: ")[1].replace("\n", "").replace(" ", "").split(",")
                ips = []
                for attacker_ip in attacker_ips:
                    attacker_ip_parts = [int(ip_part) for ip_part in attacker_ip.split(".")]
                    ip = '.'.join(map(str, attacker_ip_parts))
                    ips.append(ip)
                Attacker = ",".join(ips)
            else:
                attacker_ip = line.split("Attacker: ")[1].replace("\n", "").replace(" ", "")
                attacker_ip_parts = [int(ip_part) for ip_part in attacker_ip.split(".")]
                Attacker = '.'.join(map(str, attacker_ip_parts))
        elif line.startswith("Victim: "):
            if "," in line or "*" in line:
                victim_ips = line.split("Victim: ")[1].replace("\n", "").replace(" ", "").split(",")
                ips = []
                for victim_ip in victim_ips:
                    if "001-254" in victim_ip:
                        victim_ip_parts = [int(ip_part) for ip_part in victim_ip.split(".")[:3]]
                        victim_ip_parts.append(0)
                        for host_ip in range(1,255):
                            victim_ip_parts[3] = host_ip
                            ip = '.'.join(map(str, victim_ip_parts))
                            ips.append(ip)
                    elif "*" in victim_ip:
                        victim_ip_parts = [int(ip_part) for ip_part in victim_ip.split(".")[:3]]
                        victim_ip_parts.append(0)
                        for host_ip in range(1,255):
                            victim_ip_parts[3] = host_ip
                            ip = '.'.join(map(str, victim_ip_parts))
                            ips.append(ip)
                    else:
                        victim_ip_parts = [int(ip_part) for ip_part in victim_ip.split(".")]
                        ip = '.'.join(map(str, victim_ip_parts))
                        ips.append(ip)
                Victim = ",".join(ips)
            else:
                victim_ip = line.split("Victim: ")[1].replace("\n", "").replace(" ", "")
                victim_ip_parts = [int(ip_part) for ip_part in victim_ip.split(".")]
                Victim = '.'.join(map(str, victim_ip_parts))
        elif "At_Attacker: " in line:
            ports = line.split("At_Attacker: ")[1].replace("\n", "").replace(" ", "").split(",")
            ports_fix = []
            if ports:
                for port in ports:
                    port = port.split("{")[0]
                    port = port.split("/")[0]
                    if "-" in port:
                        start,finish = port.split('-')
                        for i in range (int(start), int(finish)+1):
                            ports_fix.append(str(i))
                    else:
                        ports_fix.append(port)
            if ports_fix:
                At_Attacker = ",".join(ports_fix)
            else:
                At_Attacker = ""
        elif "At_Victim: " in line:
            ports = line.split("At_Victim: ")[1].replace("\n", "").replace(" ", "").split(",")
            ports_fix = []
            if ports:
                for port in ports:
                    port = port.split("{")[0]
                    port = port.split("/")[0]
                    if "-" in port:
                        start,finish = port.split('-')
                        for i in range (int(start), int(finish)+1):
                            ports_fix.append(str(i))
                    else:
                        ports_fix.append(port)
            if ports_fix:
                At_Victim = ",".join(ports_fix)
            else:
                At_Victim = ""
        elif line == "\n":
            df_append = pd.DataFrame(
                [[ID, Date, Name, Category, Start_Time, Duration, Attacker, Victim, At_Attacker, At_Victim]],
                columns=columns)
            attacks_df = pd.concat([attacks_df, df_append], axis=0)

attacks_df = attacks_df.reset_index()
# Drop old index column
attacks_df = attacks_df.drop(columns="index")
attacks_df = attacks_df[attacks_df['Category'] != 'data']
attacks_df.to_csv("attack_list.csv", index=False)

print(attacks_df['Category'].value_counts())

#plt.figure(), attacks_df['Category'].value_counts().plot(kind='pie', title="Liczba typów ataków", xlabel='', ylabel=''), plt.legend(loc='best'), plt.show()
#plt.figure(), attacks_df['Category'].value_counts().plot(kind='bar',  xlabel='', ylabel=''), plt.legend(loc='lower left'), plt.yticks(), plt.show()
# sns.set(font_scale=1.4)
# attacks_df['Category'].value_counts().plot(kind='bar',  figsize=(7, 6), rot=0)
# plt.xlabel("Rodzaj ataku", labelpad=10)
# plt.ylabel("Liczba incydentów", labelpad=10)
# #plt.title("Liczba incydentów na Rodzaj ataku", y=1.02)
# plt.show()