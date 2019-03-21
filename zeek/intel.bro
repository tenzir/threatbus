@load base/frameworks/broker
@load base/frameworks/notice
@load base/frameworks/reporter

module Tenzir;

export {
	## Broker bind address.
	const broker_host = "localhost" &redef;

	## Broker port.
	const broker_port = 54321/tcp &redef;

	## Event to raise for intel item insertion.
	global add_intel: event(kind: string, value: string, source: string);

	## Event to raise for intel item removal.
	global remove_intel: event(kind: string, value: string);
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

# The enum to represent where data came from when it was discovered.
redef enum Intel::Where += {
	Intel::IN_TENZIR,
};

function is_valid_intel_type(kind: string): bool
  {
  return kind in type_map;
  }

function make_intel(kind: string, value: string,
                    source: string &default=""): Intel::Item
  {
  local result: Intel::Item = [
    $indicator = value,
    $indicator_type = type_map[kind],
    $meta = record(
      $source = source
    )
  ];
  return result;
  }

event add_intel(kind: string, value: string, source: string)
  {
  if (!is_valid_intel_type(kind))
    Reporter::fatal(fmt("got invalid intel type: %s", kind));
  print fmt("adding intel of type %s: %s", kind, value);
  Intel::insert(make_intel(kind, value, source));
  }

event remove_intel(kind: string, value: string)
  {
  if (!is_valid_intel_type(kind))
    Reporter::fatal(fmt("got invalid intel type: %s", kind));
  print fmt("removing intel of type %s: %s", kind, value);
  Intel::remove(make_intel(kind, value), T);
  }

event bro_init()
	{
	Broker::subscribe("tenzir/robo");
	Broker::listen(broker_host, broker_port);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "robo investigator connected", endpoint;
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "robo investigator disconnected", endpoint;
	}
