@load base/frameworks/broker
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/notice
@load base/frameworks/reporter

@load policy/frameworks/intel/seen

module Tenzir;

export {
  ## Threat Bus representation of intelligence.
  type Intelligence: record {
    ## A timestamp
    ts: time;
    ## A unique identifier for the intel item.
    id: string;
    ## The intel type according to Intel::Type.
    data: table[string] of string;
    ## The operation to perform (either ADD or REMOVE)
    operation: string;
  };

  ## Broker bind address.
  const broker_host = "localhost" &redef;

  ## Broker port.
  const broker_port = 47761/tcp &redef;

  ## Flag to control whether intel sightings should be reported back.
  option report_sightings = T &redef;

  ## The number of matches per second an intel item must exceed before we
  ## report it as "noisy".
  ##
  ## If 0, the computation of noisy intel will not take place.
  option noisy_intel_threshold = 100 &redef;

  ## Flag that indicates whether to log intel operations via reporter.log
  option log_operations = T &redef;

  ## Topic to subscribe to for receiving intel.
  option intel_topic = "tenzir/threatbus/intel" &redef;

  ## Topic to subscribe to for receiving intel.
  option sighting_topic = "tenzir/threatbus/sighting" &redef;

  ## The source name for the Intel framework for intel coming from Threat Bus.
  const tb_intel_tag = "threatbus";

  ## Event to raise for intel item insertion.
  ##
  ## item: The intel type to add.
  global intel: event(item: Intelligence);

  ## Event to report back sightings of (previously added) intel.
  ##
  ## ts: The timestamp when the intel has been seen.
  ##
  ## intel_id: The ID of the seen intel item.
  global sighting: event(ts: time, intel_id: string, context: table[string] of any);
}

## ---------- broker management and logging ------------------------------------

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( endpoint?$network && endpoint$network$address == broker_host 
      && endpoint$network$bound_port == broker_port && log_operations )
    Reporter::info("threatbus disconnected");
  }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( endpoint?$network && endpoint$network$address == broker_host 
      && endpoint$network$bound_port == broker_port && log_operations )
    Reporter::info("threatbus connected");
  }

# Only the manager communicates with Threat Bus.
@if ( ! Cluster::is_enabled()
      || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init() &priority=1
  {
  if ( log_operations )
    {
    Reporter::info(fmt("subscribing to topic %s", intel_topic));
    Reporter::info(fmt("reporting noisy intel at %d matches/sec",
                       noisy_intel_threshold));
    }
  Broker::subscribe(intel_topic);
  }
@endif

# If we operate in a cluster setting, we do not need to open another socket but
# instead communicate over the already existing one. The endpoint for that is
# Broker::default_listen_address and Broker::default_port
@if ( ! Cluster::is_enabled() )
event zeek_init() &priority=0
  {
  if ( log_operations )
    Reporter::info(fmt("peering to threatbus at %s:%s",
                       broker_host, broker_port));
  Broker::peer(broker_host, broker_port, 5sec);
  }
@endif

## ---------- Threat Bus specific application logic ----------------------------

# Counts the number of matches of an intel item, identified by its ID.
global sightings: table[string] of count &default=0 &create_expire=1sec;

# Maps strings to their corresponding Intel framework types. Because Broker
# cannot send enums, we must use this mapping table to obtain a native intel
# type.
global intel_type_map: table[string] of Intel::Type = {
  ["ADDR"] = Intel::ADDR,
  ["SUBNET"] = Intel::SUBNET,
  ["URL"] = Intel::URL,
  ["SOFTWARE"] = Intel::SOFTWARE,
  ["EMAIL"] = Intel::EMAIL,
  ["DOMAIN"] = Intel::DOMAIN,
  ["USER_NAME"] = Intel::USER_NAME,
  ["CERT_HASH"] = Intel::CERT_HASH,
  ["PUBKEY_HASH"] = Intel::PUBKEY_HASH,
  ["FILE_NAME"] = Intel::FILE_NAME,
  ["FILE_HASH"] = Intel::FILE_HASH,
};

# Maps a data point from Threat Bus format to a Intel::Item for the Zeek Intel
# framework
function map_to_zeek_intel(item: Intelligence): Intel::Item
  {
  local intel_item: Intel::Item = [
    $indicator = item$data["indicator"],
    $indicator_type = intel_type_map[item$data["intel_type"]],
    $meta = record(
      $desc = item$id,
      $url = tb_intel_tag, # re-used to identify Threat Bus as sending entity
      $source = tb_intel_tag
      # TODO
    )
  ];
  return intel_item;
  }

function is_mappable_intel(item: Intelligence): bool
  {
  return item?$data && "indicator" in item$data && "intel_type" in item$data && item$data["intel_type"] in intel_type_map;
  }

# Event sent by Threat Bus to indicate a change of known intelligence to Zeek.
event intel(item: Intelligence)
  {
  if ( ! is_mappable_intel(item) ) {
    Reporter::warning(fmt("ignoring unmappable intel item: %s", item));
    return;
  }

  local mapped_intel = map_to_zeek_intel(item);
  if ( log_operations )
    Reporter::info(fmt("%s intel: %s", item$operation, mapped_intel));
  if ( item$operation == "ADD" )
    Intel::insert(mapped_intel);
  else if ( item$operation == "REMOVE" )
    Intel::remove(mapped_intel, T);
  }


# Intel match events seen by the Zeek intel framework.
event Intel::match(seen: Intel::Seen, items: set[Intel::Item])
  {
  if ( ! report_sightings )
    return;
  # We only report intel that we have previously added ourselves. These intel
  # items all have a custom URL as meta data and a description with an ID.
  for ( item in items )
    {
    if ( ! item$meta?$url || item$meta$url != tb_intel_tag )
      next;
    if ( ! item$meta?$desc )
      {
      Reporter::error("skipping threatbus intel item without ID");
      next;
      }
    local intel_id = item$meta$desc;
    if ( log_operations )
      Reporter::info(fmt("sighted threatbus intel with ID: %s", intel_id));
    local n = ++sightings[intel_id];
    local noisy = noisy_intel_threshold != 0 && n > noisy_intel_threshold;
    local context: table[string] of any;
    context["noisy"] = noisy;
    Broker::publish(sighting_topic, sighting, current_time(), cat(intel_id), context);
    if ( noisy && log_operations )
      {
      Reporter::info(fmt("silencing noisy intel ID %s", intel_id));
      delete sightings[intel_id];
      }
    }
  }