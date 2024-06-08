import os
import pandas as pd
import glob
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import numpy as np

# Spans are nested inside other spans
# This function extracts only the from 'simple_telemetry.repo.query:dogs', which contains the total_time_microseconds
# Converts these spans into a new data frame
def extract_spans_from_data_frame(df):
	database_query_traces = []
	spans = df['spans']
	for span in spans:
		for trace in span:
			trace_df = pd.json_normalize(trace)

			if trace_df['operationName'].item() == 'simple_telemetry.repo.query:dogs':
				columns = {}
				columns['timestamp'] = trace_df['startTime'].item()
				for tags in trace_df['tags']:
					for tag in tags:
						tag_df = pd.json_normalize(tag)
						columns[tag_df['key'].item()] = tag_df['value'].item()
				database_query_traces.append(columns)
	return pd.DataFrame(database_query_traces)

# Reads the trace files and extract the relevant spans
def traces_json_to_data_frame(file_path: str):
	json_files = glob.glob(file_path)
	dfs = []
	for file in json_files:
		df = pd.read_json(file)
		if 'data' in df.columns:
			df = pd.json_normalize(df['data'])
		dfs.append(df)
	
	print(file_path)
	concatted = pd.concat(dfs, ignore_index=True)
	return extract_spans_from_data_frame(concatted).sort_values('timestamp')


def save_to_file(file_content, file_path):
	with open(file_path, 'w') as f:
		f.write(file_content	)

# Generates a LaTeX table
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

# Generates a table using aggregated statistics from the traces in Matplotlib and Latex format
def generate_table(data_frames: list):
	columns = ['Mean (ms)', 'Median (ms)', 'Min (ms)','p30 (ms)', 'p90 (ms)', 'Max (ms)']
	rows = []
	data = []
 
	for service_name, data_frame in data_frames:
		rows.append(service_name)

		total_time_milliseconds = data_frame['total_time_microseconds'] / 1000
		mean_value = round(total_time_milliseconds.mean(),4)
		median_value = round(total_time_milliseconds.median(),4)
		min_value = round(total_time_milliseconds.min(),4)
		max_value = round(total_time_milliseconds.max(),4)
		p30 = round(total_time_milliseconds.quantile(0.30),4)
		p90 = round(total_time_milliseconds.quantile(0.90),4)
		
		data.append([mean_value, median_value, min_value, p30, p90, max_value])

	plt.figure(figsize=(13, 5))
	plt.axis('off')

	table = plt.table(cellText=data, colLabels=columns, rowLabels=rows, cellLoc='center', loc='center', colWidths=[0.09] * 6)
	table.auto_set_font_size(False)
	table.set_fontsize(14)
	table.scale(1.5, 2)
	return generate_latex_table(column_labels=columns, row_labels=rows, data=data)

# Generates bar graphs using aggregated statistics from the traces
def generate_bar_graph(data_frames: list):
	plt.rcParams['font.size'] = '24'
	columns = ['Mean (ms)', 'Median (ms)', 'Min (ms)','p30 (ms)', 'p90 (ms)']
	rows = []
	data = []
	
	for service_name, data_frame in data_frames:
		rows.append(service_name)

		total_time_milliseconds = data_frame['total_time_microseconds'] / 1000
		mean_value = round(total_time_milliseconds.mean(),4)
		median_value = round(total_time_milliseconds.median(),4)
		min_value = round(total_time_milliseconds.min(),4)
		# max_value = round(total_time_milliseconds.max(),4)
		p30 = round(total_time_milliseconds.quantile(0.30),4)
		p90 = round(total_time_milliseconds.quantile(0.90),4)

		data.append([mean_value, median_value, min_value, p30, p90])

	x = np.arange(len(columns))
	width = 0.05 
	gap = 0.01

	fig, ax = plt.subplots(figsize=(25,15))
	for i in range(len(data)):
			ax.bar(x + i*(width+gap), data[i], width, label=rows[i])


	def format_y(value, tick_number):
			return f'{value} ms'

	formatter = FuncFormatter(format_y)
	ax.yaxis.set_major_formatter(formatter)
	ax.set_ylabel(f'total_query_time (milliseconds)')
	ax.set_title(f'total_query_time trace statistics')
	ax.set_xticks(x + width*len(data)/2 - width/2)
	ax.set_xticklabels(columns)
	ax.legend()

	# plt.show()

if __name__ == '__main__':
	test_types = ['internal']
	load_types = ['stress', 'stress700'] 
	result_folder = './results1'
	files_and_folders = os.listdir(result_folder)
 
	for test_type in test_types:
		for load_type in load_types:
			data_frames = [(name, traces_json_to_data_frame(os.path.join(result_folder, name, test_type, load_type, 'traces-*.json'))) for name in files_and_folders if os.path.isdir(os.path.join(result_folder, name))]
			save_to_file(generate_table(data_frames), f'./new_plots/trace/{test_type}/{load_type}_latex_table.txt')
			# plt.tight_layout()
			# Table format
			plt.savefig(f'./new_plots/trace/{test_type}/{load_type}_table.png')
			plt.clf()
			print(f"Generating plot for {test_type}, {load_type}")
	 
			# Bar graphs
			generate_bar_graph(data_frames)
			plt.tight_layout()
			plt.savefig(f'./new_plots/trace/{test_type}/{load_type}_bar_graph.png')
			plt.clf()




		
			