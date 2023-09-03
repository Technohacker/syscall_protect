import argparse
parser = argparse.ArgumentParser("extract.py")
parser.add_argument("executable_file", help="The executable file to extract a syscall graph from. NOTE: This must point to a statically linked binary")

args = parser.parse_args()

# Setup logging
from loguru import logger as log

# Extractor import is kept separate since importing angr takes a while
log.info("Loading extractor...")
import extractor

# Start extracting!
log.info("Extractor loaded. Extracting...")
extractor.extract_scg(args.executable_file)
