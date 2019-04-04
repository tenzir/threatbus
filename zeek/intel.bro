@load base/frameworks/broker
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

  ## Flag that indicates whether to log intel operations via reporter.log
  const log_operations = T &redef;

  ## Topic to subscribe to for receiving intel.
  const robo_investigator_topic = "tenzir/robo" &redef;

  ## The source name for the Intel framework for intel coming from the robo.
  const intel_source_name = "tenzir";

  ## Event to raise for intel item insertion.
  ##
  ## kind: The intel type in
  global add_intel: event(kind: string, value: string, id: string);

  ## Event to raise for intel item removal.
  global remove_intel: event(kind: string, value: string);

  ## Event to report back sightings of (previously added) intel.
  ##
  ## ts: The timestamp when the intel has been seen.
  ##
  ## ids: The set of IDs that identify the intel items.
  global intel_report: event(ts: time, ids: set[string]);

  ## Event to raise when requesting a full snapshot of intel.
  ##
  ## source: The source of the intel as recorded in the Intel framework.
  global intel_snapshot_request: event(source: string);

  ## Response event to :bro:id:`intel_snapshot_request`.
  ##
  ## items: The intel items in the snapshot.
  global intel_snapshot_reply: event(items: vector of Intelligence);

  ## PRIVATE

  # Flag to avoid duplicate requests of intel snapshots.
  # It is only exported because we need to access to the internal state of the
  # Intel framework. Do not modify this value.
  global intel_snapshot_received = F;
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
};

function is_valid_intel_type(kind: string): bool
  {
  return kind in type_map;
  }

function make_intel(kind: string, value: string,
                    id: string &default=""): Intel::Item
  {
  local result: Intel::Item = [
    $indicator = value,
    $indicator_type = type_map[kind],
    $meta = record(
      $desc = id,
      $source = intel_source_name
    )
  ];
  return result;
  }

function insert(item: Intelligence)
  {
  if ( !is_valid_intel_type(item$kind) )
    Reporter::fatal(fmt("got invalid intel type: %s", item$kind));
  if ( log_operations )
    Reporter::info(fmt("adding intel of type %s: %s", item$kind, item$value));
  Intel::insert(make_intel(item$kind, item$value, item$id));
  }

function remove(item: Intelligence)
  {
  if ( !is_valid_intel_type(item$kind) )
    Reporter::fatal(fmt("got invalid intel type: %s", item$kind));
  if ( log_operations )
    Reporter::info(fmt("removing intel of type %s: %s", item$kind, item$value));
  Intel::remove(make_intel(item$kind, item$value), T);
  }

event add_intel(kind: string, value: string, id: string)
  {
  insert([$id=id, $kind=kind, $value=value]);
  }

event remove_intel(kind: string, value: string)
  {
  # The intel framework doesn't index intelligence by what we define as ID,
  # which is why we don't need it here. If we were to try to remove by ID, we'd
  # have to perform an O(n) search where n is the number of items that Zeek
  # keeps track of. Consequently, we identify intel by type and value.
  remove([$id="", $kind=kind, $value=value]);
  }

export {
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
    result += Tenzir::Intelligence(
      $id=data_store$host_data[x][source]$desc,
      $kind="ADDR",
      $value=cat(x)
    );
  for ( y in data_store$subnet_data )
    result += Tenzir::Intelligence(
      $id=data_store$subnet_data[y][source]$desc,
      $kind="SUBNET",
      $value=cat(y)
    );
  for ( [z, kind] in data_store$string_data )
    result += Tenzir::Intelligence(
      $id=data_store$string_data[z, kind][source]$desc,
      $kind=cat(kind),
      $value=cat(z)
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
    Broker::publish(robo_investigator_topic,
                    intel_snapshot_request,
                    intel_source_name);
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
  # We only report intel that we have previously added ourselves.
  local ids: set[string];
  ids = set();
  for ( item in items )
    if ( item$meta?$desc && item$meta$source == intel_source_name )
      add ids[item$meta$desc];
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

event bro_init()
  {
  Broker::subscribe(robo_investigator_topic);
  Broker::listen(broker_host, broker_port);
  }
