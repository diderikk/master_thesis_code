import pandas as pd
from datetime import datetime, timedelta
import os

for root, dirs, files in os.walk('./results2-copy'):
    # Get a list of all resource_metrics.csv files in the current directory
    csv_files = [f for f in files if f.endswith('resource_metrics.csv')]
    print(root)
    print(csv_files)

    # Loop through each file
    for file in csv_files:
        df = pd.read_csv(os.path.join(root, file))

        for i in range(1, len(df)):
            # print(int(df.iloc[i, -1]))
            # If the difference between the current timestamp and the previous one is 1 second
            if abs(df.iloc[i, -1] - df.iloc[i-1, -1]) == 1:
                print(df.iloc[i, -1], df.iloc[i-1, -1])
                # Set the current timestamp to the previous one
                df.iloc[i, -1] = df.iloc[i-1, -1]

        df.to_csv(os.path.join(root, file), index=False)