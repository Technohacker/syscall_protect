import argparse
parser = argparse.ArgumentParser("extract.py")
parser.add_argument("executable_file", help="The executable file to extract a syscall graph from. NOTE: This must point to a statically linked binary")
parser.add_argument("dot_result", help="Output path for the DOT graph")
parser.add_argument("policy_result", help="Output path for the policy file")

args = parser.parse_args()

# Setup logging
from loguru import logger as log

# Extractor import is kept separate since importing angr takes a while
log.info("Loading extractor...")
import extractor

# Start extracting!
log.info("Extractor loaded. Invoking...")
cfg = extractor.extract_cfg(args.executable_file)
scg = extractor.extract_scg(cfg)

import networkx
networkx.nx_agraph.write_dot(scg, args.dot_result)

import policy_maker
policy_maker.save_policy(scg, args.policy_result)
