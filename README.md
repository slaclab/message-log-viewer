## message-log-viewer

A user interface for reading entries in the acceleartor message logs. LCLS, FACET, and TESTFAC are all included. Both reading live log data and querying historical data are supported, with filtering options provided for both use cases. Communicates with the [Loki](https://grafana.com/oss/loki/) instance running in S3DF where the log data is stored.

## Requirements

* Python 3.9+
* requests
* qtpy
* A Qt Python wrapper

## Installation

Currently this application is not hosted anywhere else, so `pip install .`
