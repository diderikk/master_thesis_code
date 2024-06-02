import csv
import time
import requests
from datetime import datetime
from prometheus_client.parser import text_string_to_metric_families
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

previous_cpu_usage = {}
ELAPSED_TIME = 10

def get_current_time():
	# Get the current time
	current_time = datetime.now()

	return int(current_time.timestamp())

def calculate_core_usage(sample, pod_container):
  return int(round(sample[2] - previous_cpu_usage[pod_container], 8) * 1000) // ELAPSED_TIME

# def calculate_node_core_usage

def scrape_resource_metrics(worker_node_ip: str, token: str, namespaces: list[str], current_time: int):
	containers = []
	container_memory = {}
	headers = {'Authorization': f'Bearer {token}'}
	metrics_response = requests.get(f"https://{worker_node_ip}:10250/metrics/resource", headers=headers, verify=False)
	metric_families = text_string_to_metric_families(metrics_response.text)

	# Metric(container_cpu_usage_seconds, [ALPHA] Cumulative cpu time consumed by the container in core-seconds
	# Metric(container_memory_working_set_bytes, [ALPHA] Current working set of the container in bytes

	for family in metric_families:
		if "container_memory_working_set_bytes" == family.name or "container_cpu_usage_seconds" == family.name:
			for sample in family.samples:
				labels = sample[1]
				if 'namespace' in labels and labels['namespace'] in namespaces:
					print(sample)
					pod_name = labels['pod']

					container_name = labels['container']
					pod_container = pod_name + container_name
					namespace = labels['namespace']
     
					if pod_container in container_memory.keys():
						if family.name == "container_memory_working_set_bytes":
							container_memory[pod_container]["memory_usage"] = int(sample[2] // 1024)
						else:
							if pod_container in previous_cpu_usage.keys():
								container_memory[pod_container]["cpu_usage"] = calculate_core_usage(sample, pod_container)
							else:
								container_memory[pod_container]["cpu_usage"] = 0

							previous_cpu_usage[pod_container] = sample[2]
       
						containers.append(container_memory[pod_container])
					else:
						if family.name == "container_memory_working_set_bytes":
							container_memory[pod_container] = {'pod': pod_name, 'namespace': namespace, 'container': container_name,
	 								'memory_usage': int(sample[2] // 1024), 'time': current_time}
						else:
							if pod_container in previous_cpu_usage.keys():
								container_memory[pod_container] = {'pod': pod_name, 'namespace': namespace, 'container': container_name,
	 								'cpu_usage': calculate_core_usage(sample, pod_container), 'time': current_time}
							else:
								container_memory[pod_container] = {'pod': pod_name, 'namespace': namespace, 'container': container_name,
	 								'cpu_usage': 0, 'time': current_time}

							previous_cpu_usage[pod_container] = sample[2]
  
	return containers

def scrape_node_metrics(worker_node_ip: str, token: str, worker_index: int, current_time: int):
	nodes = []
	node_memory = {}
	headers = {'Authorization': f'Bearer {token}'}

	metrics_response = requests.get(f"https://{worker_node_ip}:10250/metrics/resource", headers=headers, verify=False)
	metric_families = text_string_to_metric_families(metrics_response.text)

	# node_cpu_usage_seconds_total: Cumulative cpu time consumed by the node in core-seconds
	# node_memory_working_set_bytes: Current working set of the node in bytes

	for family in metric_families:
		if "node_memory_working_set_bytes" == family.name or "node_cpu_usage_seconds" == family.name:
			for sample in family.samples:
				print(sample)
				node_name = f"worker{worker_index}"

				
				if node_name in node_memory.keys():
					if family.name == "node_memory_working_set_bytes":
						node_memory[node_name]["memory_usage"] = int(sample[2] // 1024)
					else:
						if node_name in previous_cpu_usage.keys():
							node_memory[node_name]["cpu_usage"] = calculate_core_usage(sample, node_name)
						else:
							node_memory[node_name]["cpu_usage"] = 0

						previous_cpu_usage[node_name] = sample[2]
			
					nodes.append(node_memory[node_name])
				else:
					if family.name == "container_memory_working_set_bytes":
						node_memory[node_name] = {'pod': node_name, 'namespace': '', 'container': '',
								'memory_usage': int(sample[2] // 1024), 'time': current_time}
					else:
						if node_name in previous_cpu_usage.keys():
							node_memory[node_name] = {'pod': node_name, 'namespace': '', 'container': '',
								'cpu_usage': calculate_core_usage(sample, node_name), 'time': current_time}
						else:
							node_memory[node_name] = {'pod': node_name, 'namespace': '', 'container': '',
								'cpu_usage': 0, 'time': current_time}

						previous_cpu_usage[node_name] = sample[2]
	return nodes


if __name__ == "__main__":
	TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkVseVZOc0JuaG1XbEFPc0ZDRFJPVEJaUko5TXpJVmtMV0xyWUI0S0ZXQUUifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzE3NTI5Njc1LCJpYXQiOjE3MTczMTM2NzUsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwic2VydmljZWFjY291bnQiOnsibmFtZSI6Im1ldHJpY3Mtc2NyYXBlciIsInVpZCI6IjAyMzNhZmUyLWVlZDQtNDU0Mi1hNWJjLWE2MGRkYWU5ZTdlMiJ9fSwibmJmIjoxNzE3MzEzNjc1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDptZXRyaWNzLXNjcmFwZXIifQ.hTHjNXdqqaAGqyV7waOgXAQhF6omz1LnoDxcdoBo-uHH9QxLqbysq5sTUN_qOX4sSHW6_GwWDbUpiUd5B0hF9Ex2P4q_D-46lXLLRmtbyoQzgZZwD77syA8ptN4jU0Gx9NSv_KFvdW-6kiB38gIBtjBW7t_oLciK-mnThCurYuRQHfOJ6lqFXeYH6bS2MirwGM-VoA19xt1kSco_5zZQHuyHjHJub0LYJRj4AyWPQDv5TJVDzgmM3kS5239NK1Fkt0vhpTOg0UKvMC1pQTPmFWhy_-Nqw3jNbTnUOQs9y4FqxklcQsAZumqlgGOxGyjgqy9jvFgJDTRSOKLx63GJVQ" # kubectl create token metrics-scraper --duration 3600m
	WORKER_NODE_IPS = ["192.168.86.158", "192.168.86.159", "192.168.86.160"]
	NAMESPACES = ["default", 'istio-system']

	with open('resource_metrics.csv', 'w', newline='') as csvfile:
		fieldnames = ['pod', 'namespace', 'container', 'cpu_usage', 'memory_usage', 'time']
		writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
		writer.writeheader()

		index = 0
		while True:
			container_metrics = []
			node_metrics = []
			
			current_time = get_current_time()
			for i, ip in enumerate(WORKER_NODE_IPS):
				container_metrics.extend(scrape_resource_metrics(ip, TOKEN, NAMESPACES, current_time))
				node_metrics.extend(scrape_node_metrics(ip, TOKEN, i, current_time))

			# Initialize the previous_cpu_usage directory/map in the first iteration
			if index != 0:
				writer.writerows(container_metrics)
				writer.writerows(node_metrics)
			index += 1
			time.sleep(ELAPSED_TIME)