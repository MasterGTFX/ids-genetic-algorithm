#
#
# print("lol")
# import preprocessing
# print("lol 2")
# import processing_fix
# print("lol 3")
# import processing_attackers
# print("done")
#
# # import pandas as pd
# # df = pd.read_csv("dataset1_fix.csv", low_memory=False, header=0)
# # print(df.dtypes)
# # print(df[:100000])

import pandas as pd

ints = list(range(10))

df = pd.DataFrame(ints, columns=['int'])

for index,row in df[df['int'].isin([1,4,5])].iterrows():
    print(index)
