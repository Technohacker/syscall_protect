import angr
import collections
import itertools

from loguru import logger as log
from pprint import pprint

import networkx

def extract_cfg(file_path: str) -> angr.analyses.cfg.CFGFast:
    # Load the project and TODO: all debug symbols associated
    log.info("Loading project...")
    proj = angr.Project(file_path, load_options={"auto_load_libs": False}, load_debug_info = False)
    log.info("Project loaded")
    # proj.kb.dvars.load_from_dwarf()

    # Extract the control flow graph (CFG)
    log.info("Extracting CFG, this may take a while...")
    cfg: angr.analyses.cfg.CFGFast = proj.analyses.CFGFast(
        normalize=True,
        show_progressbar=True,
    )
    log.info("CFG Extracted")

    # TODO: See if this is necessary
    # log.info("Re-constructing function instances...")
    # cfg.make_functions()
    # log.info("Function instances re-constructed")

    return cfg

def extract_scg(cfg: angr.analyses.cfg.CFGFast) -> networkx.DiGraph:
    G = cfg.graph

    log.info(f"# of nodes present: {len(G.nodes())}")

    # Point Syscall edges to the immediate next fallthrough node (if present)
    log.info(f"Redirecting syscall edges...")
    for node in G.nodes():
        edges = list(G.out_edges(node, data=True))
        edge_count = len(edges)

        for i in range(edge_count):
            # Skip any non-syscall edges
            (_, syscall_node, syscall_data) = edges[i]
            if syscall_data["jumpkind"] != "Ijk_Sys_syscall":
                continue

            # We're at the end of this node's edges, there are no more fakerets
            if i == edge_count - 1:
                continue

            (_, fallthrough_node, fallthrough_data) = edges[i + 1]
            if fallthrough_data["jumpkind"] != "Ijk_FakeRet":
                continue

            # Make sure we don't accidentally clobber more fakerets by changing the jumpkind
            syscall_data["jumpkind"] = f"Syscall: {syscall_node.name}"
            G.remove_edge(node, syscall_node)
            networkx.set_edge_attributes(G, {
                (node, fallthrough_node): syscall_data
            })

    # Build partitions of the CFG based on connected boring nodes
    log.info(f"Building partitions...")
    partitions = []
    covered = set()
    for node in G.nodes():
        if node in covered:
            continue
        
        # Find all nodes reachable from this node with boring edges
        queue: collections.deque[angr.analyses.cfg.CFGNode] = collections.deque([node])
        partition = set()
        while len(queue) > 0:
            n = queue.popleft()
            if n in covered or n in partition:
                continue

            partition.add(n)
            covered.add(n)

            for (_, v, data) in G.out_edges(n, data=True):
                if data["jumpkind"] in ["Ijk_Boring", "Ijk_FakeRet"]:
                    queue.append(v)

        partitions.append(partition)

    log.info(f"Partitions built, # of nodes expected in SCG: {len(partitions)}")

    # Build the SCG by using quotient graphs
    log.info(f"Building SCG, this may take a while...")
    scg = networkx.quotient_graph(
        G,
        partitions,
        edge_relation=lambda a, b: len(networkx.node_boundary(G, a, b)) > 0,
        edge_data=lambda a, b: {
            "label": G.get_edge_data(*(list(networkx.edge_boundary(G, a, b))[0]))["jumpkind"],
        },
        node_data=lambda partition: {
            "label": list(partition)[0].name,
        },
    )
    log.info(f"SCG built, # of nodes: {len(scg.nodes())}. # of edges: {len(scg.edges())}")

    return scg
