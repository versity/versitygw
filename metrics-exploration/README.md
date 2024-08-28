# Versity Gateway Dashboard

This project is a dashboard that visualizes data in the six metrics emitted by the Versity Gateway, displayed in Grafana. 

The Versity Gateway emits metrics in the statsd format. We used Telegraf as the bridge from statsd to influxdb.

This implementation uses the influxql query language. 

## Usage

From the root of this repository, run `docker compose -f docker-compose-metrics.yml up` to start the stack.

To shut it down, run `docker compose -f docker-compose-metrics.yml down -v`. 

The Grafana database is explicitly not destroyed when shutting down containers. The influxdb one, however, is.

The dashbaord is automatically provisioned at container bring up and is visible at http://localhost:3000 with  username: `admin` and password: `admin`.

To use the gateway and generate metrics, `source metrics-exploration/aws_env_setup.sh` and start using your aws cli as usual.