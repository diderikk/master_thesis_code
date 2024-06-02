import pandas as pd
import pandas as pd
import os
from matplotlib.ticker import FuncFormatter
import numpy as np

import matplotlib.pyplot as plt


def metric_csv_to_data_frame(file_path: str):
	df = pd.read_csv(file_path).sort_values('time')
 	# Convert KiB to MiB => for readability
	df['memory_usage'] = df['memory_usage'] / 1024 
 	# Convert n to m => for readability
	# df['cpu_usage'] = df['cpu_usage'] / 1_000_000  
	return df

def save_to_file(file_content, file_path):
	with open(file_path, 'w') as f:
		f.write(file_content	)

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

def generate_plots(data_frames: list, pods: dict, metrics_names: list):
	plt.rcParams['font.size'] = '17'

	tmp_pods = pods
	
	if 'total' in pods.keys():
		pods = {'total': 'Total'}
  
	fig, axs = plt.subplots(len(pods.keys()), len(metrics_names), figsize=(25, 10))
	for i, pod in enumerate(pods.keys()):
		for j, (metric_name, metric_unit, metric_title) in enumerate(metrics_names):
			ax = axs[j]
			if(len(pods.keys()) != 1):
				ax = axs[i][j]

		
			for service_name, data_frame in data_frames:
				min_time = None
				pod_data = data_frame[data_frame['pod'].str.startswith(pod)]
				if pod == 'total':
					pod_data = data_frame[data_frame['pod'].str.startswith(tuple(tmp_pods.keys()))]
				mean_values = pod_data.groupby('time')[metric_name].sum()

				if min_time is None:
					min_time = mean_values.index.min()
				mean_values.index -= min_time
				ax.plot(mean_values.index, mean_values, label=service_name)

			def make_format_y(metric_unit):
				def format_y(value, tick_number):
						return f'{int(value)}{metric_unit}'
				return format_y

			def format_x(value, tick_number):
				return f'{int(value)}s'

			formatter = FuncFormatter(make_format_y(metric_unit))
			ax.yaxis.set_major_formatter(formatter)
			formatter = FuncFormatter(format_x)
			ax.xaxis.set_major_formatter(formatter)

			if i == len(pods.keys()) - 1:
				ax.set_xlabel('Time s')
			ax.set_ylabel(f'{metric_title} Usage {metric_unit}')
			ax.set_title(f'{metric_title} Usage {pods.get(pod)}')
			ax.legend()


def generate_table(data_frames: list, pods: dict, metrics_names: list):
	columns = []
	rows = {}
 
	tmp_pods = pods
	
	if 'total' in pods.keys():
		pods = {'total': 'Total'}
	
	for pod in pods.keys():
		rows[pod] = []
 
	for metric_name, metric_unit, metric_title in metrics_names:
		columns.extend([f'{metric_title} Mean {metric_unit}', f'{metric_title} p70 {metric_unit}', f'{metric_title} p90 {metric_unit}',
			f'{metric_title} Max {metric_unit}'])
	for service_name, data_frame in data_frames:
		for pod in pods.keys():
			curr_data = []
			for metric_name, metric_unit, metric_title in metrics_names:
				pod_data = data_frame[data_frame['pod'].str.startswith(pod)].groupby('time')[metric_name].sum()
				if pod == 'total':
					pod_data = data_frame[data_frame['pod'].str.startswith(tuple(tmp_pods.keys()))].groupby('time')[metric_name].sum()
				mean_value = round(pod_data.mean(),4)
				p70 = round(pod_data.quantile(0.70),4)
				p90 = round(pod_data.quantile(0.90),4)
				max_value = round(pod_data.max(),4)
				curr_data.extend([mean_value, p70, p90, max_value])
			rows[pod].append((service_name,curr_data))

	row_label = []
	data = []
	for k, pod in enumerate(rows.keys()):
		for i, (service_name, curr_data) in enumerate(rows.get(pod)):
			row_label.append(f'{pods.get(pod)} {service_name}')
			data.append(curr_data)

			if i == len(rows.get(pod)) - 1 and k != len(rows.keys()) - 1:
				row_label.append(f'')
				data.append(['', '', '', '', '', '', '', ''])
	plt.axis('off')
	table = plt.table(cellText=data, colLabels=columns, rowLabels=row_label, cellLoc='center', loc='center', 
                   colWidths=[0.09] * 8)
	table.auto_set_font_size(False)
	table.set_fontsize(14)
	table.scale(1.2, 2)
	return generate_latex_table(column_labels=columns, row_labels=row_label, data=data)
	
 
def generate_bar_graph(data_frames: list, pods: dict, metrics_names: list, test_type: str, load_type: str):
    tmp_pods = pods
    plt.rcParams['font.size'] = '17'
    
    if 'total' in pods.keys():
        pods = {'total': 'Total'}
    
    for metric_name, metric_unit, metric_title in metrics_names:
        columns = [f'{metric_title} Mean {metric_unit}', f'{metric_title} p70 {metric_unit}', f'{metric_title} p90 {metric_unit}',
            f'{metric_title} Max {metric_unit}']
        data = []
        labels = []
        for service_name, data_frame in data_frames:
            for pod in pods.keys():
                curr_data = []
                pod_data = data_frame[data_frame['pod'].str.startswith(pod)].groupby('time')[metric_name].sum()
                if pod == 'total':
                    pod_data = data_frame[data_frame['pod'].str.startswith(tuple(tmp_pods.keys()))].groupby('time')[metric_name].sum()
                mean_value = round(pod_data.mean(),4)
                p70 = round(pod_data.quantile(0.70),4)
                p90 = round(pod_data.quantile(0.90),4)
                max_value = round(pod_data.max(),4)
                curr_data.extend([mean_value, p70, p90, max_value])
                data.append(curr_data)
                labels.append(f'{pods.get(pod)} {service_name}')

        x = np.arange(len(columns))
        width = 0.05 
        gap = 0.01

        fig, ax = plt.subplots(figsize=(25,15))
        for i in range(len(data)):
            ax.bar(x + i*(width+gap), data[i], width, label=labels[i])
            
            
        def make_format_y(metric_unit):
          def format_y(value, tick_number):
            return f'{int(value)}{metric_unit}'
          return format_y
        
        formatter = FuncFormatter(make_format_y(metric_unit))
        ax.yaxis.set_major_formatter(formatter)
        ax.set_ylabel(f'{metric_title} Usage {metric_unit}')
        ax.set_title(f'{metric_title} Usage')
        ax.set_xticks(x + width*len(data)/2 - width/2)
        ax.set_xticklabels(columns)
        ax.legend()

        plt.savefig(f'./new_plots/resource_consumtion/{test_type}/{load_type}_{metric_name}_total_bar_graph.png')


if __name__ == '__main__':
	test_types = ['internal']
	load_types = ['stress200', 'stress500', 'stress700', 'spike']
	result_folder = './results2-copy'
	files_and_folders = os.listdir(result_folder)
	pods = {}
	metrics = [('memory_usage', 'MiB', 'Memory'), ('cpu_usage', 'm', 'CPU')]
	file_paths = []
 
	
	for test_type in test_types:
		if test_type == "external":
			pods = {'simple': 'HTTP Server', 'database': 'Database'}
			pods = {'worker': 'Node Total'}
		else:
			pods = {'distributed-k6-test': 'HTTP Client', 'simple': 'HTTP Server', 'database': 'Database', 'traefik-mesh-proxy': 'Proxy'}
			pods = {'worker': 'Node Total'}
   
		for load_type in load_types:
			file_paths = [(name, os.path.join(result_folder, name, load_type, 'resource_metrics.csv')) for name in files_and_folders if os.path.isdir(os.path.join(result_folder, name))]
			data_frames = []
			for name, path in file_paths:
				df = metric_csv_to_data_frame(path)
				data_frames.append((name, df))
			# plt.subplots_adjust(left=0, right=1, bottom=0, top=1, wspace=0, hspace=0)
			# plt.tight_layout()
			print(f"Generating plot for test type: {test_type}, load_type: {load_type}")
			# generate_plots(data_frames, pods, metrics)
			# plt.savefig(f'./plots/resource_consumtion/{test_type}/{load_type}_graph.png')
			# plt.clf()

			# save_to_file(generate_table(data_frames, pods, metrics), f'./plots/resource_consumtion/{test_type}/{load_type}_latex_table.txt')
			# plt.savefig(f'./plots/resource_consumtion/{test_type}/{load_type}_table.png')
			# plt.clf()
   
			pods['total'] = 'Total'
			generate_plots(data_frames, pods, metrics)
			plt.savefig(f'./new_plots/resource_consumtion/{test_type}/{load_type}_total_graph.png')
			plt.clf()
   
			# save_to_file(generate_table(data_frames, pods, metrics), f'./plots/resource_consumtion/{test_type}/{load_type}_latex_total_table.txt')
			# plt.clf()
			generate_bar_graph(data_frames, pods, metrics, test_type, load_type)
			plt.clf()
   