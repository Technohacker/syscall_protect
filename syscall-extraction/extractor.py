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
            (_, next_node, next_data) = edges[i]
            # Check the edge type. Syscall edges must be redirected, Call edges should have their FakeRet clobbered
            jumpkind = next_data["jumpkind"]
            if jumpkind == "Ijk_Sys_syscall":
                # Make sure we don't accidentally clobber more fakerets, done by changing the jumpkind
                # Edit the jumpkind now to make sure we also edit syscalls with no remaining path
                next_data["jumpkind"] = f"Syscall"
                next_data["syscall_name"] = next_node.name

                # We're at the end of this node's edges, there are no more fakerets
                if i == edge_count - 1:
                    continue

                (_, fallthrough_node, fallthrough_data) = edges[i + 1]
                if fallthrough_data["jumpkind"] != "Ijk_FakeRet":
                    print(f"Non-fakeret edge found after syscall? {fallthrough_data}")
                    continue

                G.remove_edge(node, next_node)
                networkx.set_edge_attributes(G, {
                    (node, fallthrough_node): next_data
                })
            elif jumpkind == "Ijk_Call":
                # Clobber the immediate next FakeRet if any exist
                if i == edge_count - 1:
                    continue

                (_, fallthrough_node, fallthrough_data) = edges[i + 1]
                if fallthrough_data["jumpkind"] != "Ijk_FakeRet":
                    print(f"Non-fakeret edge found after call? {fallthrough_data}")
                    continue

                G.remove_edge(node, fallthrough_node)

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
                    # Don't merge nodes if they're the destination of a syscall or a call return
                    merge = True
                    for (_, _, in_data) in G.in_edges(v, data=True):
                        if in_data["jumpkind"] in ["Syscall", "Ijk_Ret"]:
                            merge = False
                            break

                    if merge:
                        queue.append(v)

        partitions.append(partition)

    log.info(f"Partitions built, # of nodes expected in SCG: {len(partitions)}")

    # Build the SCG by using quotient graphs
    log.info(f"Building SCG, this may take a while...")
    def should_edge_exist(a, b):
        node_boundary = networkx.node_boundary(G, a, b)

        return len(node_boundary) > 0

    def edge_data(a, b):
        boundary = list(networkx.edge_boundary(G, a, b))
        edges_data = [G.get_edge_data(u, v) for (u, v) in boundary]
        label = [data["jumpkind"] + " " + data.get("syscall_name", "") for data in edges_data]

        return {
            "label": label,
        }

    scg = networkx.quotient_graph(
        G,
        partitions,
        edge_relation=should_edge_exist,
        edge_data=edge_data,
        node_data=lambda partition: {
            "label": list(partition)[0].name,
        },
    )
    log.info(f"SCG built, # of nodes: {len(scg.nodes())}. # of edges: {len(scg.edges())}")

    return scg
