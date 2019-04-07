@load base/frameworks/broker
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/notice
@load base/frameworks/reporter

@load policy/frameworks/intel/seen

module Tenzir;

export {
  ## A space-efficient represenattion of intelligence.
  type Intelligence: record {
    ## A unique identifier for the intel item.
    id: string;
    ## The intel type according to Intel::Type.
    kind: string;
    ## The value of the indicator.
    value: string;
    ## The origin of the intel.
    source: string;
  };

  ## Broker bind address.
  const broker_host = "localhost" &redef;

  ## Broker port.
  const broker_port = 54321/tcp &redef;

  ## Flag to control whether to request an intel snapshot upon successfully
  ## establishing a peering.
  const request_snapshot = T &redef;

  ## Flag to control whether intel that matches should be reported back.
  const report_intel = T &redef;

  ## The number of matches per second an intel item must exceed before we
  ## report it as "noisy.
  ##
  ## If 0, the computation of noisy intel will not take place.
  const noisy_intel_threshold = 100 &redef;

  ## Flag that indicates whether to log intel operations via reporter.log
  const log_operations = T &redef;

  ## Topic to subscribe to for receiving intel.
  const robo_investigator_topic = "tenzir/robo" &redef;

  ## The source name for the Intel framework for intel coming from the robo.
  const robo_intel_tag = "Tenzir Robo Investigator";

  ## Event to raise for intel item insertion.
  ##
  ## item: The intel type to add.
  global add_intel: event(item: Intelligence);

  ## Event to raise for intel item removal.
  ##
  ## item: The intel type to remove.
  global remove_intel: event(item: Intelligence);

  ## Event to report back sightings of (previously added) intel.
  ##
  ## ts: The timestamp when the intel has been seen.
  ##
  ## ids: The set of IDs that identify the intel items.
  global intel_report: event(ts: time, ids: set[string]);

  ## Event to report back when intel matches exceed `noisy_intel_threshold`.
  ##
  ## id: The ID of the intel item.
  ##
  ## n: The number of matches per second of this item.
  global noisy_intel_report: event(id: string, n: count);

  ## Event to raise when requesting a full snapshot of intel.
  ##
  ## source: The source of the intel as recorded in the Intel framework.
  global intel_snapshot_request: event(source: string);

  ## Response event to :bro:id:`intel_snapshot_request`.
  ##
  ## items: The intel items in the snapshot.
  global intel_snapshot_reply: event(items: vector of Intelligence);
}

# Maps string to their corresponding Intel framework types. Because Broker
# cannot send enums, we must use this mapping table to obtain a native intel
# type.
global type_map: table[string] of Intel::Type = {
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

# Counts the number of matches of an intel item, identified by its ID.
global intel_matches: table[string] of count &default=0 &create_expire=1sec;

function is_valid_intel_type(kind: string): bool
  {
  if ( kind in type_map )
    return T;
  Reporter::warning(fmt("ignoring invalid intel type: %s", kind));
  return F;
  }

function make_intel(x: Intelligence): Intel::Item
  {
  local result: Intel::Item = [
    $indicator = x$value,
    $indicator_type = type_map[x$kind],
    $meta = record(
      $source = x$source,
      $desc = x$id,
      $url = robo_intel_tag
    )
  ];
  return result;
  }

function insert(item: Intelligence)
  {
  if ( !is_valid_intel_type(item$kind) )
    return;
  if ( log_operations )
    Reporter::info(fmt("adding intel %s", item));
  Intel::insert(make_intel(item));
  }

function remove(item: Intelligence)
  {
  if ( !is_valid_intel_type(item$kind) )
    return;
  if ( log_operations )
    Reporter::info(fmt("removing intel %s", item));
  Intel::remove(make_intel(item), T);
  }

event add_intel(item: Intelligence)
  {
  insert(item);
  }

event remove_intel(item: Intelligence)
  {
  remove(item);
  }

export {
  # Only exported because we need to access it below from the Intel module.
  global intel_snapshot_received = F;
}

module Intel;

event Tenzir::intel_snapshot_request(source: string)
  {
  # There exists a race condition when we have just started up and not received
  # a response to our initial snapshot request. Then this request will return
  # an empty set. To prevent this, we postpone the execution of this event
  # until the snapshot has arrived.
  if ( Tenzir::request_snapshot && ! Tenzir::intel_snapshot_received )
    {
    schedule 1sec { Tenzir::intel_snapshot_request(source) };
    return;
    }
  if ( Tenzir::log_operations )
    Reporter::info(fmt("got request for snapshot for source %s", source));
  local result: vector of Tenzir::Intelligence = vector();
  for ( x in data_store$host_data )
    if ( source == "" )
      for ( src in data_store$host_data[x] )
        result += Tenzir::Intelligence(
          $id=data_store$host_data[x][src]$desc,
          $kind="ADDR",
          $value=cat(x),
          $source=src
        );
    else if ( source in data_store$host_data[x] )
      result += Tenzir::Intelligence(
        $id=data_store$host_data[x][source]$desc,
        $kind="ADDR",
        $value=cat(x),
        $source=source
      );
  for ( y in data_store$subnet_data )
    if ( source == "" )
      for ( src in data_store$host_data[x] )
        result += Tenzir::Intelligence(
          $id=data_store$subnet_data[y][src]$desc,
          $kind="SUBNET",
          $value=cat(y),
          $source=src
        );
    else if ( source in data_store$subnet_data[y] )
      result += Tenzir::Intelligence(
        $id=data_store$subnet_data[y][source]$desc,
        $kind="SUBNET",
        $value=cat(y),
        $source=source
      );
  for ( [z, kind] in data_store$string_data )
    if ( source == "" )
      for ( src in data_store$host_data[x] )
        result += Tenzir::Intelligence(
          $id=data_store$string_data[z, kind][src]$desc,
          $kind=cat(kind),
          $value=cat(z),
          $source=src
        );
    else if ( source in data_store$string_data[z, kind] )
      result += Tenzir::Intelligence(
        $id=data_store$string_data[z, kind][source]$desc,
        $kind=cat(kind),
        $value=cat(z),
        $source=source
      );
  if ( Tenzir::log_operations )
    Reporter::info(fmt("sending snapshot with %d intel items", |result|));
  Broker::publish(Tenzir::robo_investigator_topic,
                  Tenzir::intel_snapshot_reply, result);
  }

module Tenzir;

event intel_snapshot_reply(items: vector of Intelligence)
  {
  intel_snapshot_received = T;
  if ( log_operations )
    Reporter::info(fmt("got intel snapshot with %d items", |items|));
  for ( i in items )
    insert(items[i]);
  }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( log_operations )
    Reporter::info(fmt("robo investigator connected: %s", endpoint));
  if ( request_snapshot && ! intel_snapshot_received )
    {
    if ( log_operations )
      Reporter::info("requesting current snapshot of intel");
    local source = ""; # We want all intel
    Broker::publish(robo_investigator_topic, intel_snapshot_request, source);
    }
  }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
  {
  if ( log_operations )
    Reporter::info(fmt("robo investigator disconnected: %s", endpoint));
  }

@if ( report_intel )
event Intel::match(seen: Intel::Seen, items: set[Intel::Item])
  {
  # We only report intel that we have previously added ourselves. These intel
  # items all have a custom URL as meta data and a description with an ID.
  local ids: set[string] = set();
  for ( item in items )
    if ( item$meta?$url && item$meta$url == robo_intel_tag )
      {
      if ( ! item$meta?$desc )
        Reporter::fatal("description must be present for robo intel");
      local id = item$meta$desc;
      if ( noisy_intel_threshold == 0 )
        {
        add ids[id];
        }
      else
        {
        local n = ++intel_matches[id];
        if ( n < noisy_intel_threshold )
          {
          add ids[id];
          }
        else
          {
          if ( log_operations )
            Reporter::info(fmt("reporting noisy intel ID %s", id));
          Broker::publish(robo_investigator_topic, Tenzir::noisy_intel_report,
                          id, n);
          Intel::remove(item, T);
          delete intel_matches[id];
          }
        }
      }
  if ( |ids| == 0 )
    return;
  local e = Broker::make_event(intel_report, current_time(), ids);
  Broker::publish(robo_investigator_topic, e);
  if ( log_operations )
    {
    local value: string;
    if ( seen?$indicator )
      value = seen$indicator;
    else
      value = cat(seen$host);
    Reporter::info(fmt("reporting %s intel match(es) for %s", |ids|, value));
    }
  }
@endif

# Only the manager communicates with Robo.
@if ( ! Cluster::is_enabled() 
      || Cluster::local_node_type() == Cluster::MANAGER )
event bro_init() &priority=1
  {
  if ( log_operations )
    {
    Reporter::info(fmt("subscribing to topic %s", robo_investigator_topic));
    Reporter::info(fmt("reporting noisy intel at %d matches/sec",
                       noisy_intel_threshold));
    }
  Broker::subscribe(robo_investigator_topic);
  }
@endif

# If we operate in a cluster setting, we do not need to open another socket but
# instead communicate over the already existing one. The endpoint for that is
# Broker::default_listen_address and Broker::default_port
@if ( ! Cluster::is_enabled() )
event bro_init() &priority=0
  {
  if ( log_operations )
    {
    Reporter::info(fmt("listening at %s:%s for robo investigator",
                       broker_host, broker_port));
    }
  Broker::listen(broker_host, broker_port);
  }
@endif
