import os
import pandas as pd
import glob
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import gzip
import shutil
import numpy as np

# All files are stored in gzipped file
# This commands unzips the files and writes it to a new CSV file in the same location
def decompress_gzip(file_path):
	with gzip.open(file_path, 'rb') as f_in:
		with open(file_path[:-3] + ".csv", 'wb') as f_out:
			shutil.copyfileobj(f_in, f_out)

# Converts k6 CSV files to pandas dataframes
def metric_csv_to_data_frame(file_path: str):
	csv_files = glob.glob(file_path)
	dfs = []
	for file in csv_files:
		df = pd.read_csv(file, low_memory=False)
		dfs.append(df)
		
	# Multiple CSV files per test since k6 deploys 10 pods per test, each writting to their own file
	concatted = pd.concat(dfs, ignore_index=True).sort_values('timestamp')
	
	# Removes failed HTTP request
	failed_req_df = concatted[(concatted['metric_name'] == 'http_req_failed') & (concatted['metric_value'] > 0)]
	failed_timestamps = failed_req_df['timestamp'].unique()
	return concatted[~concatted['timestamp'].isin(failed_timestamps)]
  
def save_to_file(file_content, file_path):
	with open(file_path, 'w') as f:
		f.write(file_content	)

# Generates a latex table
def generate_latex_table(column_labels, row_labels, data):
	latex_table = "\\begin{table}\n\\centering\n\\resizebox{\\columnwidth}{!}{\\begin{tabular}{|" + "l|" * (len(column_labels) + 1) + "}\n"

	latex_table += "\\hline\n"
	latex_table += " & " + " & ".join(column_labels) + " \\\\\n"
	latex_table += "\\hline\n"

	for row_label, row_data in zip(row_labels, data):
			row_data = ["\\large{" + str(item) + "}" for item in row_data]
			latex_table += row_label + " & " + " & ".join(map(str, row_data)) + " \\\\\n"
			latex_table += "\\hline\n"

	latex_table += "\\end{tabular}}\n\\end{table}"

	return latex_table

# Aggregates statistics from the CSV files to be used as a time series
def generate_data_frame_from_metric_files(file_path: str, metric_name: str):

	combined_df = metric_csv_to_data_frame(file_path)
	# Virtual users data frame
	vus_df = combined_df[(combined_df['metric_name'] == 'vus') & (
		combined_df['metric_value'] > 0)].groupby('timestamp')['metric_value'].sum().reset_index(drop=True)
	# Request duration data frame, this is used to generate metrics
	req_dur_df = combined_df[combined_df['metric_name'] == metric_name].groupby('timestamp')['metric_value']

	mean_df = req_dur_df.mean().rolling(window=3).mean().reset_index(drop=True)
	p90 = req_dur_df.quantile(0.90).rolling(
		window=3).mean().reset_index(drop=True)
	p70 = req_dur_df.quantile(0.70).rolling(
		window=3).mean().reset_index(drop=True)
	p30 = req_dur_df.quantile(0.30).rolling(
		window=3).mean().reset_index(drop=True)

	return vus_df, mean_df, p90, p70, p30

# Aggregates statistics from the CSV files
def generate_stats_from_metric_files(file_path: str, metric_name: str):
	combined_df = metric_csv_to_data_frame(file_path)

	mean_target_vus = combined_df[combined_df['metric_name'] == "vus_max"].groupby(
		'timestamp')['metric_value'].sum().mean()
	mean_vus = combined_df[combined_df['metric_name'] == "vus"].groupby(
		'timestamp')['metric_value'].sum().mean()

	# Request duration data frame, this is used to generate metrics
	metric_df = combined_df[combined_df['metric_name'] == metric_name]['metric_value']
	median = metric_df.median()
	mean = metric_df.mean()
	p10 = metric_df.quantile(0.10)
	p30 = metric_df.quantile(0.30)
	p70 = metric_df.quantile(0.70)
	p90 = metric_df.quantile(0.90)
	minimum = metric_df.min()

	return mean_target_vus, mean_vus, median, mean, minimum, p10, p30, p70, p90

# Generates a time series plot
def generate_plots(file_paths: list, metric_name: str):
	data = {
		'mean': [],
		# 'p90': [],
		# 'p70': [],
		# 'p30': []
	}
	for name, file_path in file_paths:
		vus, mean, p90, p70, p30 = generate_data_frame_from_metric_files(
			file_path, metric_name)
		data['mean'].append((name, mean))
		# data['p90'].append((name, p90))
		# data['p70'].append((name, p70))
		# data['p30'].append((name, p30))
		
	rows = 1
	# fig, axs = plt.subplots(rows, 2, figsize=(15, 2 * len(data.keys())))

	for i, metric_aggregation in enumerate(data.keys()):
		row = i // 2
		col = i % 2
		plt.rcParams['font.size'] = '17'
		ax = plt.subplot(rows, 1, i+1)
		# ax.fill_between(vuss[0].index, vuss[0], alpha=0.2, label='VUS')
		# ax.plot(vuss[0], label='VUS line')
		for name, metric in data[metric_aggregation]:
			ax.plot(metric, label=name)

		def format_y(value, tick_number):
			return f'{value}ms'

		def format_x(value, tick_number):
			return f'{value}s'

		formatter = FuncFormatter(format_y)
		ax.yaxis.set_major_formatter(formatter)
		formatter = FuncFormatter(format_x)
		ax.xaxis.set_major_formatter(formatter)

		ax.set_xlabel('Time s')
		ax.set_ylabel(f'{metric_name} ms')
		ax.set_title(f'Mean HTTP Request Duration')
		ax.legend()

# Generates the plots that show the staging of VUS	
def generate_VU_plot(file_paths: list, metric_name: str, load_type: str):
	vuss = []
	for name, file_path in file_paths:
		vus, mean, p90, p70, p30 = generate_data_frame_from_metric_files(
			file_path, metric_name)
		vuss.append(vus)
	
	fig, ax = plt.subplots()
	
	ax.fill_between(vuss[0].index, vuss[0], alpha=0.2, label='VUS')
	ax.plot(vuss[0], label='VUS line')
	
	def format_y(value, tick_number):
		return f'{value}VUs'

	def format_x(value, tick_number):
		return f'{value}s'

	formatter = FuncFormatter(format_y)
	ax.yaxis.set_major_formatter(formatter)
	formatter = FuncFormatter(format_x)
	ax.xaxis.set_major_formatter(formatter)

	ax.set_xlabel('Time s')
	ax.set_ylabel(f'Virtual Users (VUs)')
	ax.set_title(f'{load_type} Test Staging')
	ax.legend()

# Generates a row (from one service)
def generate_row(file_path: str, metric_name: str):
	mean_target_vus, mean_vus, median, mean, minimum, p10, p30, p70, p90 = generate_stats_from_metric_files(
		file_path, metric_name)

	return [round(mean_target_vus, 4), 
			round(mean_vus, 4), 
			round(median, 4), 
			round(mean, 4),
			round(minimum, 4), 
			round(p10, 4), 
			round(p30, 4), 
			round(p70, 4), 
			round(p90, 4)]

# Generates a table of metrics from all services in LaTeX and Matplotlib formats
def generate_table(file_paths: list, metric_name: str):
	columns = ['Median (ms)',
			   'Mean (ms)', 'Minimum (ms)', 'p10 (ms)', 'p30 (ms)', 'p70 (ms)', 'p90 (ms)']
	rows = []
	data = []

	for name, file_path in file_paths:
		rows.append(name)
		data.append(generate_row(file_path, metric_name)[2:])

	plt.axis('off')
	table = plt.table(cellText=data, colLabels=columns,
					  rowLabels=rows, cellLoc='center', loc='center')
	table.auto_set_font_size(False)
	table.set_fontsize(13)
	table.scale(1, 2)
	return generate_latex_table(column_labels=columns, row_labels=rows, data=data)

# Generates bar graphs using metrics from all services
def generate_bar_graph(file_paths: list, metric_name: str):
	plt.rcParams['font.size'] = '17'
	columns = ['Median', 'Mean', 'Minimum', 'p10', 'p30', 'p70', 'p90']
	labels = []
	data = []

	for name, file_path in file_paths:
		labels.append(name)
		data.append(generate_row(file_path, metric_name)[2:])

	x = np.arange(len(columns))
	width = 0.07 
	gap = 0.01 

	fig, ax = plt.subplots(figsize=(20,15))
	for i in range(len(data)):
		ax.bar(x + i*(width+gap), data[i], width, label=labels[i])


	def format_y(value, tick_number):
		return f'{value}ms'

	formatter = FuncFormatter(format_y)
	ax.yaxis.set_major_formatter(formatter)

	ax.set_ylabel('HTTP Request Duration (milliseconds)')
	ax.set_title(f'{metric_name} metric statistics')
	ax.set_xticks(x + width*len(data)/2 - width/2)
	ax.set_xticklabels(columns)
	ax.legend()


if __name__ == '__main__':
	test_types = ['internal']
	load_types = ['stress200','stress500','stress700','spike'] # 
	result_folder = './results2-copy'
	files_and_folders = os.listdir(result_folder)
	
	for test_type in test_types:
		for load_type in load_types:
			file_paths = []
			if test_type == 'external':
				[decompress_gzip(os.path.join(result_folder, name, load_type, 'k6-run.gz')) for name in files_and_folders if os.path.isdir(os.path.join(result_folder, name))]
			
				file_paths = [(name, os.path.join(result_folder, name, load_type, 'k6-run.csv')) for name in files_and_folders if os.path.isdir(os.path.join(result_folder, name))]
			else:
				test_folders = [os.path.join(result_folder, name, load_type, 'tests') for name in files_and_folders if os.path.isdir(os.path.join(result_folder, name))]
				
				for test_folder in test_folders:
					test_files = [f for f in os.listdir(test_folder) if f.endswith('.gz')]
					for test_file in test_files:
						decompress_gzip(os.path.join(test_folder, test_file))
				
				file_paths = [(name, os.path.join(result_folder, name, load_type, 'tests', '*.csv')) for name in files_and_folders if os.path.isdir(os.path.join(result_folder, name))]
			
			print(file_paths)
			metric_names = ['http_req_duration']
			# Time series graphs
			for i, metric_name in enumerate(metric_names):
				plt.figure(i, figsize=(15, 10))
				generate_plots(file_paths, metric_name)
				plt.tight_layout()
			plt.savefig(f'./new_plots/request/{test_type}/{load_type}_graph.png')
			plt.clf()
			
			# VUs staging graph
			# for i, metric_name in enumerate(metric_names):
			#     plt.figure(i, figsize=(15, 10))
			#     generate_VU_plot(file_paths, metric_name, load_type)
			#     plt.tight_layout()
			# plt.savefig(f'./new_plots/request/{test_type}/{load_type}_VUs_graph.png')
			# plt.clf()

			# Table (LaTeX and png)
			for i, metric_name in enumerate(metric_names):
				plt.figure(i + len(metric_names), figsize=(15, 6))
				save_to_file(generate_table(file_paths, metric_name), f'./new_plots/request/{test_type}/{load_type}_latex_table.txt')
				plt.tight_layout()
			plt.savefig(f'./new_plots/request/{test_type}/{load_type}_table.png')
			plt.clf()
			
			# Bar graphs
			for i, metric_name in enumerate(metric_names):
				# plt.figure(i, figsize=(25, 15))
				generate_bar_graph(file_paths, metric_name)
				plt.tight_layout()
			plt.savefig(f'./new_plots/request/{test_type}/{load_type}_bar_graph.png')
			plt.clf()

# Metrics in the CSV files:
#     ['vus' 'vus_max' 'http_reqs' 'http_req_duration' 'http_req_blocked'
#    'http_req_connecting' 'http_req_tls_handshaking' 'http_req_sending'
#    'http_req_waiting' 'http_req_receiving' 'http_req_failed' 'data_sent'
#    'data_received' 'iteration_duration' 'iterations']
