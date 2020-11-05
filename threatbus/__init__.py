import pluggy
from .threatbus import ThreatBus, start
from .stoppable_worker import StoppableWorker

app = pluggy.HookimplMarker("threatbus.app")
"""Marker to be imported and used in app-plugins"""

backbone = pluggy.HookimplMarker("threatbus.backbone")
"""Marker to be imported and used in backbone-plugins"""
