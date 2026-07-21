"""Target adapter layer — everything that knows how to talk to a system under test.

The platform is built to generalize beyond one target: a `TargetAdapter` names the
base URL, endpoint map, auth mode, and the safety invariants an attack tries to
falsify. Swapping targets is a config change, not a rewrite.
"""
