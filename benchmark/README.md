Benchmarking
============

This folder provides experimental benchmarking tools to measure message passing
performance for some Threat Bus plugins.

Benchmarks are executed via the script `simple-bench`. All benchmarks must be
executed from within the `benchmark` folder, because subsequent invocations are
performed relatively to the current working directory of the caller.

## Using the Benchmark Script

You must install Threat Bus and required plugins before you execute the script.
It is required that the installation happens in a virtual enviroment called
`venv` that is located at the toplevel of this repository.

```
virtualenv venv
source venv/bin/activate

# main threatbus
pip install -e .

# zmq-app plugin
pip install -e plugins/apps/threatbus_zmq_app

# benchmark backbone to publish faked messages
pip install -e plugins/backbones/file_benchmark

# rabbit backbone
pip install -e plugins/backbones/threatbus_rabbitmq

# start benchmarking
cd benchmark
./simple-bench.sh <options>
```

Start benchmarking when you have installed all the above packages. Invoke the
`simple-bench.sh` script always from within the `benchmark` folder. The script
takes four arguments:

1. The type of the benchmark (either `rabbit_consumer` or `zmq`)
2. The number of rounds to run
3. The number of events to send in one round
4. A sleep interval. The script will idle in that time and give the tested
  resources time to execute, before the script collects the results.

You need to test good values for the last parameter on your own machine.

NOTE: for `zmq` we recommend a timeout of at least 3 seconds, because the
`file_benchmark` backbone waits 2 seconds before starts provisioning messages.

### Example Calls

- Run three rounds, consume 1000 items from RabbitMQ
  ```
  ./simple-bench.sh rabbit_consumer 3 100 1
  ```
- Run 10 rounds, publish 100 items via ZeroMQ
  ```
  ./simple-bench.sh zmq 3 10 3
  ```

### The `benchmark_config.yaml`

This file is used as configuration for Threat Bus. Depending on your benchmark
type you *must* change it. You have two options:

1. Enable the RabbitMQ backbone plugin, disable everything else
2. Enable the `zmq-app` and `file_benchmark` plugins, disable everything else

## Interpreting the Results

The `simple-bench.sh` script prints the time-different of the first and last
processed messages. Let's discuss this on an example:

```
./simple-bench.sh rabbit_consumer 3 10 1

Benchmarking RabbitMQ consumer
Calculating the difference between first and last message processed, in milliseconds:
3.00006
2.00013
1.99987
```

In this example, we run three benchmarks and consume 10 events from RabbitMQ per
run. The total amount of milliseconds spent for each run is then printed to the
console. If you were to run 12 runs you would get 12 result prints.

