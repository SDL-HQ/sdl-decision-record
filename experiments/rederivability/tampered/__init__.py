"""Tampered copies of the Cedar decider, as a dishonest producer's own module.

Each module changes exactly one producer-side step and nothing else. Crucially
each keeps `DECIDER_ID` and `DECIDER_VERSION` identical to the honest module:
the version string names the *engine* (`cedarpy-<release>`) and says nothing
about the wrapper that builds the request, so a record made by any of these
names the same decider as an honest one, byte for byte.

These exist to be caught. They are never used to make a record anyone is asked
to believe, and the keys they are signed with are generated from a fixed label
at run time and are not production keys.
"""
