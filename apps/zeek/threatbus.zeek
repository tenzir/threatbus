@load base/frameworks/broker
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/notice
@load base/frameworks/reporter

@load policy/frameworks/intel/seen

module Tenzir;

export {
  ## Threat Bus representation of intelligence items (IoCs).
  type Intelligence: record {
    ## A timestamp
    ts: time;
    ## A unique identifier for the intel item.
    id: string;
    ## The intel type according to Intel::Type.
    intel_type: string;
    ## The IoC value, e.g., "evil.com"
    indicator: string;
    ## The operation to perform (either ADD or REMOVE)
    operation: string;
  };

  ## Broker bind address.
  option broker_host = "127.0.0.1" &redef;

  ## Broker port.
  option broker_port = 47761/tcp &redef;

  ## The source name for the Intel framework for intel coming from Threat Bus.
  const tb_intel_tag = "threatbus";

  ## Flag to control whether intel sightings should be reported back.
  option report_sightings = T &redef;

  ## The number of matches per second an intel item must exceed before we
  ## report it as "noisy".
  ##
  ## If 0, the computation of noisy intel will not take place.
  option noisy_intel_threshold = 100 &redef;

  ## Flag that indicates whether to log intel operations via reporter.log
  option log_operations = T &redef;

  ## Threat Bus topic to subscribe to for receiving intel.
  option intel_topic = "stix2/indicator" &redef;

  ## Event to raise for intel item insertion.
  ##
  ## item: The intel type to add.
  global intel: event(item: Intelligence);

  ## Threat Bus topic to report sightings.
  option sighting_topic = "stix2/sighting" &redef;

  ## Event to report back sightings of (previously added) intel.
  ##
  ## ts: The timestamp when the intel has been seen.
  ##
  ## intel_id: The ID of the seen intel item.
  global sighting: event(ts: time, intel_id: string, context: table[string] of any);

  ## Broker topic to negotiate un/subscriptions with Threat Bus.
  option management_topic = "threatbus/manage" &redef;

  ## Point-to-point topic for this Zeek instance to Threat Bus.
  ##
  ## The p2p_topic will be created by Threat Bus and all data coming on that
  ## topic is meant for this particular Zeek instance only.
  global p2p_topic: string = "" &redef;

  ## Event to subscribe a new topic at Threat Bus.
  ##
  ## topic: The topic we are interested in
  ##
  ## snapshot: The earliest timestamp for which to request a snapshot for.
  global subscribe: event(topic: string, snapshot_intel: interval);

  ## Event raised by Threat Bus when new subscriptions are acknowledged.
  ## The returned p2p_topic is only valid for this Zeek instance.
  ##
  ## p2p_topic: a dedicated topic for this Zeek instance to subscribe to
  global subscription_acknowledged: event(p2p_topic: string);

  ## Event to unsubscribe a topic from Threat Bus.
  ##
  ## topic: The topic we are interested in
  global unsubscribe: event(topic: string);

  ## The earliest timestamp for which to request a snapshot for.
  option snapshot_intel: interval = 0 sec &redef;

}

## ---------- broker management and logging ------------------------------------

# Predicate for checking if Zeek is already subscribed to Threat Bus
function is_subscribed(): bool
  {
  return p2p_topic != "";
  }

# Unsubscribe from the Threat Bus p2p_topic by sending an `Unsubscribe` event
# via Broker to the Threat Bus Zeek plugin's management endpoint.
function unsubscribe_p2p()
  {
  if ( log_operations )
    Reporter::info(fmt("unsubscribing from p2p_topic %s", p2p_topic));
  Broker::publish(management_topic, unsubscribe, p2p_topic);
  p2p_topic = ""; # invalidate old p2p_topic
  }

# Subscribe to Threat Bus by sending a `Subscribe` event via Broker to the
# Threat Bus Zeek plugin's management endpoint.
function subscribe_p2p()
  {
  Broker::publish(management_topic, subscribe, intel_topic, snapshot_intel);
  }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( endpoint?$network && endpoint$network$address == broker_host 
      && endpoint$network$bound_port == broker_port && log_operations )
    Reporter::info("Threat Bus unpeered");
  }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( endpoint?$network && endpoint$network$address == broker_host 
      && endpoint$network$bound_port == broker_port )
    if ( log_operations )
      Reporter::info("Threat Bus peered");
    if ( is_subscribed() )
      {
      # Already peered, so Zeek has lost connection to Threat Bus. The reason
      # for the connection loss is unclear. If the Threat Bus host has died we
      # need to invalidate our old p2p_topic. If it has not, and we invalidate
      # the p2p_topic, Threat Bus will be left with a dangling subscription.
      # So we unsubsribe our old p2p_topic entirely and re-subscribe.
      unsubscribe_p2p();
      }
    subscribe_p2p();
  }

# Only the manager communicates with Threat Bus.
@if ( ! Cluster::is_enabled()
      || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init() &priority=1
  {
  if ( log_operations )
    {
    Reporter::info(fmt("subscribing to management topic %s with snapshot request for %s",
                       management_topic, snapshot_intel));
    Reporter::info(fmt("reporting noisy intel at %d matches/sec",
                       noisy_intel_threshold));
    }
  # explicitly use management topic to register a subscription with snapshot
  Broker::subscribe(management_topic);
  }
@endif

# The manager peers with Threat Bus.
@if ( ! Cluster::is_enabled()
      || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init() &priority=0
  {
  if ( log_operations )
    Reporter::info(fmt("peering with Threat Bus at %s:%s",
                       broker_host, broker_port));
  Broker::peer(broker_host, broker_port, 5sec);
  }
@endif

# Only the manager communicates with Threat Bus.
@if ( ! Cluster::is_enabled()
      || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_done() &priority=1
  {
  unsubscribe_p2p();
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
    $indicator = item$indicator,
    $indicator_type = intel_type_map[item$intel_type],
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
  return item?$indicator && item?$intel_type && item$intel_type in intel_type_map;
  }

# Event sent by Threat Bus to publish a new intelligence item (IoC) to Zeek.
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

# Event sent by Threat Bus to acknowledge new subscriptions.
event subscription_acknowledged(topic: string)
  {
  # Avoid picking up p2p_topics from other Zeek instances. This is a shortcoming
  # of Broker, as we cannot avoid seeing all messages on the management topic. 
  if ( is_subscribed() )
    return;

  # This particular topic is used by Threat Bus to send peer-to-peer messages to
  # this Zeek instance only.
  p2p_topic = topic;
  Broker::subscribe(p2p_topic);
  if ( log_operations )
    Reporter::info(fmt("Subscribed to p2p_topic: %s", p2p_topic));
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
      Reporter::error("skipping Threat Bus intel item without ID");
      next;
      }
    local intel_id = item$meta$desc;
    if ( log_operations )
      Reporter::info(fmt("sighted Threat Bus intel with ID: %s", intel_id));
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
