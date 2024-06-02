import os
import pandas as pd

# Define conversion factors
MI_TO_KI = 1024
M_TO_NANO = 1_000_000
U_TO_NANO = 1_000

# Walk through all subdirectories in the ./results1 directory
for root, dirs, files in os.walk('./results1'):
    # Get a list of all resource_metrics.csv files in the current directory
    csv_files = [f for f in files if f.endswith('resource_metrics.csv')]

    # Loop through each file
    for file in csv_files:
        # Load the CSV file into a pandas DataFrame
        df = pd.read_csv(os.path.join(root, file))

        # Convert memory from Mi to Ki and convert to int
        df['memory_usage'] = df['memory_usage'].astype(str).apply(lambda x: int(float(x.rstrip('Mi')) * MI_TO_KI) if 'Mi' in x else int(float(x)))

        # Convert CPU usage from m (millicores) and u (microcores) to nanocores and convert to int
        df['cpu_usage'] = df['cpu_usage'].astype(str).apply(lambda x: int(float(x.rstrip('m')) * M_TO_NANO) if 'm' in x else int(float(x.rstrip('u')) * U_TO_NANO) if 'u' in x else int(float(x)))

        # Save the DataFrame back to the CSV file
        df.to_csv(os.path.join(root, file), index=False)