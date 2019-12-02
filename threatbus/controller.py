import asyncio
import logging
import sys

from zeek import to_zeek
from misp import Action

PYTHON_3_6 = (3, 6, 6, 'final', 0)

def async_create_task(f):
    if sys.version_info <= PYTHON_3_6:
        return asyncio.ensure_future(f)
    else:
        return asyncio.create_task(f)

class Controller:
    def __init__(self, vast, misp, zeek):
        self.logger = logging.getLogger("threat-bus.controller")
        self.vast = vast
        self.misp = misp
        self.zeek = zeek
        # List of intel IDs that we have received from Zeek and forwarded to
        # MISP for IDS flag removal. Once MISP removes the IDS flag, we will
        # receive an updated attribute without IDS flag. We ignore such an
        # update because Zeek already deleted the intel item along with
        # reporting it as noisy.
        self.noisy_intel = []

    async def run(self):
        self.logger.debug("starting main loop")
        zeek = None
        misp = None
        while True:
            if not zeek:
                self.logger.debug("scheduling Zeek task")
                zeek = async_create_task(self.zeek.get())
            if not misp:
                self.logger.debug("scheduling MISP task")
                misp = async_create_task(self.misp.intel())
            done, pending = await asyncio.wait(
                [zeek, misp],
                timeout=1,
                return_when=asyncio.FIRST_COMPLETED)
            if zeek in done:
                event = zeek.result()
                args = event.args()
                zeek = None
                if event.name() == "Tenzir::intel_snapshot_request":
                    self.logger.debug("retrieving snapshot from MISP")
                    snapshot = await self.misp.snapshot()
                    items = [x for x in map(to_zeek, snapshot) if x]
                    incompatible = len(snapshot) - len(items)
                    if incompatible > 0:
                        self.logger.warning(f"ignored {incompatible} "
                                            "intel items")
                    self.logger.debug(f"sending Zeek {len(items)} "
                                      "intel items")
                    self.zeek.put("Tenzir::intel_snapshot_reply", items)
                elif event.name() == "Tenzir::intel_snapshot_reply":
                    assert len(args) == 1
                    def make_intel(xs):
                        assert len(xs) == 4
                        return {
                            "desc": xs[0],
                            "type": xs[1],
                            "value": xs[2],
                            "source": xs[3],
                        }
                    snapshot = [make_intel(xs) for xs in args[0]]
                    print(json.dumps(snapshot))
                    return
                elif event.name() == "Tenzir::intel_report":
                    timestamp, ids = args
                    assert ids
                    self.logger.info(f"Zeek saw intel {ids} at {timestamp}")
                    if self.misp:
                        self.logger.debug(f"reporting {len(ids)} sightings "
                                          "from Zeek to MISP")
                        ts = int(timestamp.timestamp())
                        for id in ids:
                            await self.misp.report(id, ts)
                elif event.name() == "Tenzir::noisy_intel_report":
                    assert len(args) == 2
                    attr_id, n = args
                    self.logger.info("got report of noisy attribute "
                                     f"{attr_id} with {n.value} matches/sec")
                    self.misp.propose_removal_of_ids_flag(attr_id)
                    self.noisy_intel.append(attr_id)
            if misp in done:
                action, intel = misp.result()
                misp = None
                if action in [Action.ADD, Action.EDIT]:
                    if self.vast:
                        expr = self.vast.make_expression(intel)
                        results = await self.vast.export(expr)
                        self.logger.debug(f"reporting {len(results)} sightings "
                                          "from VAST to MISP")
                        for result in results:
                            self.logger.debug(result)
                            record = json.loads(result)
                            if "ts" not in record:
                                self.logger.critical(
                                    "no 'ts' column in Zeek log")
                            timestamp = int(record["ts"])
                            await self.misp.report(intel.id, timestamp)
                    if self.zeek:
                        self.zeek.add_intel(intel)
                elif action == Action.REMOVE:
                    if self.zeek:
                        if intel.id in self.noisy_intel:
                            self.logger.debug(f"ignorying noisy intel update")
                            self.noisy_intel.remove(intel.id)
                        else:
                            self.zeek.remove_intel(intel)
