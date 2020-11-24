#!/usr/bin/env sh

rabbit_consumer() {
  # Injects messages into RabbitMQ, then starts Threat Bus and measures raw consumption times.
  rm threatbus.log
  python rabbitmq_sender.py "$1"

  threatbus -c benchmark_config.yaml &
  tb=$!
  sleep "$2"
  count=$(grep -c 'Relayed message from RabbitMQ' threatbus.log)
  if [ "$count" != "$1" ]; then
    echo "Fewer messages logged than sent! Try increasing the sleep interval: $count/$1"
  fi
  grep 'Relayed message from RabbitMQ' threatbus.log | sed -n '1p;$p' | awk -F ' ' '{print $2}' | awk 'NR > 1 {"date -d "$0" +%s%N"|getline a; "date -d "prev" +%s%N"|getline b; print (a-b)/1000000} {prev=$0}'

  kill "$tb"
}

zmq() {
  # Starts Threat Bus and sends messages to `zmq-app` plugin endpoint. Starts a dummy consumer. Measures roundtrip of receiving and publishing messages.
  rm threatbus.log
  config=benchmark_config.yaml
  sed -i.bak -e 's/foo/bar/' -- "$config"
  rm -- "$config.bak"
  threatbus -c "$config" &
  tb=$!
  sleep 0.5
  python ../tests/utils/zmq_receiver.py "$1" 1>/dev/null &
  sleep "$2"
  count=$(grep -c 'Published' threatbus.log)
  if [ "$count" != "$1" ]; then
    echo "Fewer messages logged than sent! Try increasing the sleep interval: $count/$1"
  fi
  grep 'Published' threatbus.log | sed -n '1p;$p' | awk -F ' ' '{print $2}' | awk 'NR > 1 {"date -d "$0" +%s%N"|getline a; "date -d "prev" +%s%N"|getline b; print (a-b)/1000000} {prev=$0}'

  kill "$tb"
}


if [ "$#" != 4 ]; then
  {
    echo Invoke with './simple-bench.sh <type> <runs> <messages> <sleep>'
    echo "<type>: either 'rabbit_consumer' or 'zmq'"
    echo "<runs>: number of runs to execture, e.g., 10"
    echo "<messages>: number of messages to send in one run, e.g., 1000"
    echo "<sleep>: number of seconds to wait for each <messages> for Threat Bus to collect them"
    echo "Example: ./simple-bench.sh rabbit 10 10000 5    # execute 10 runs, send 10000 messages in each run, wait 5 seconds each run before collecting results" 
  } >&2
  exit 1
fi

if [ "$1" = "rabbit_consumer" ]; then
  echo "Benchmarking RabbitMQ consumer"
  echo "Calculating the difference between first and last message processed, in milliseconds:"
  for _ in $(seq 1 "$2"); do
    rabbit_consumer "$3" "$4"
  done
elif [ "$1" = "zmq" ]; then
  echo "Benchmarking ZMQ consumer"
  echo "Calculating the difference between first and last message processed, in milliseconds:"
  for _ in $(seq 1 "$2"); do
    zmq "$3" "$4"
  done
else
  echo "unknown bench"
fi
