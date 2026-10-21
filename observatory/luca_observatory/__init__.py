#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Luca Kernel-Native Network Observatory - Python side.

    Standard library only, so that the analysis engine, the frontend, the
    collector service and the experiments can all import it without new
    dependencies. The eBPF collector itself is the C program in ../src.

    Provenance labels used throughout:
      OBSERVED     measured directly by one telemetry source;
      CORRELATED   the same activity recorded by two independent collection
                   paths (for example the kernel classifier and the capture);
      INFERRED     a conclusion drawn from observations by a heuristic;
      UNAVAILABLE  the telemetry needed for a statement is missing.
"""

VERSION = "1.0.0"

SNAPSHOT_SCHEMA = "luca.observatory/1"
SUMMARY_SCHEMA = "luca.observatory.summary/1"
SESSION_SCHEMA = "luca.observatory.session/1"
MANIFEST_SCHEMA = "luca.observatory.manifest/1"

OBSERVED = "OBSERVED"
CORRELATED = "CORRELATED"
INFERRED = "INFERRED"
UNAVAILABLE = "UNAVAILABLE"
LABELS = (OBSERVED, CORRELATED, INFERRED, UNAVAILABLE)

# Observation categories. Every observation carries exactly one.
CORROBORATED = "corroborated"   # independent sources agree
SINGLE_SOURCE = "single_source" # only one source recorded it
UNCERTAIN = "uncertain"         # correlated, but the match is ambiguous or inconsistent
MISSING = "missing"             # telemetry absent or incomplete
INFERENCE = "inferred"          # heuristic conclusion drawn from observations
CATEGORIES = (CORROBORATED, SINGLE_SOURCE, UNCERTAIN, MISSING, INFERENCE)
