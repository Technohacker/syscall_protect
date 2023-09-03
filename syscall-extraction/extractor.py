import angr
import collections
import itertools

from loguru import logger as log
from pprint import pprint

import networkx

def extract_scg(file_path):
    # Load the project and TODO: all debug symbols associated
    log.info("Loading project...")
    proj = angr.Project(file_path, load_options={"auto_load_libs": False}, load_debug_info = False)
    log.info("Project loaded")
    # proj.kb.dvars.load_from_dwarf()

    # Extract the control flow graph (CFG)
    log.info("Extracting CFG, this may take a while...")
    cfg: angr.analyses.cfg.CFGEmulated = proj.analyses.CFGEmulated(
        context_sensitivity_level=1,
        enable_function_hints=True,
        normalize=True,
    )
    log.info("CFG Extracted")

    # TODO: See if this is necessary
    # log.info("Re-constructing function instances...")
    # cfg.make_functions()
    # log.info("Function instances re-constructed")

    log.info(f"# of functions present: {len(cfg.functions)}")

    # Build the syscall graph from the CFG
    # Start traversal from the binary's entry point
    entry_nodes = cfg.model.get_all_nodes(proj.entry)
    assert len(entry_nodes) == 1, "Binary entry point had multiple contexts!"

    queue = collections.deque([entry_nodes[0]])
    visited = set()
    while len(queue) > 0:
        node = queue.popleft()
        if node in visited:
            continue

        visited.add(node)
        print(f"\n[{node.addr:x}] {node.name}")

        # Don't skip the fake returns, since those actually tell us where syscalls return
        for (succ, jmp) in node.successors_and_jumpkinds(excluding_fakeret=False):
            print(f"\t{jmp} to [{succ.addr:x}] {succ.name}")
            if succ not in visited:
                queue.append(succ)

    return proj