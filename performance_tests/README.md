# Performance tests
This folder contains all the scripts used to perform the performance tests and the plots representing the metrics extracted during the tests. The performance tests are divided into requests (HTTP request latency), resource consumption, and traces (database query time).

## Folder structure

* **Installation-scripts**: Contains all the Bash scripts configuring the Kubernetes cluster and deploying components onto it. The components consist of services tested and observability components that were used to extract data during the performance tests. [installation-scripts/all.md](./installation-scripts/all.md) described the general procedure of testing one service.
* **k6-scripts**: Contains the k6 test scripts used during the tests. Each test execution is similar, only differing in the staging of virtual users during the test.
* **Kubernetes-deployments**: Contains all the YAML files used to deploy the necessary components onto the Kubernetes cluster. Most of these are referenced in the **Installation-scripts** descriptions.
* **plots**: Contains the generated plots from the Python programs in **python-scripts**. The data is based on the metrics gathered from running the tests.
* **python-scripts**: Contains the Python script used to continuously scrape resource usage metrics from the Kubernetes cluster during the performance tests. In addition, the folder contains the scripts used to generate the plots in folder **plots**.