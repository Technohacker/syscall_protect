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
    redirect_syscall_edges(G)
    log.info(f"Clobbering function call fakerets...")
    clobber_call_fakeret_edges(G)

    # Build partitions of the CFG based on connected boring nodes
    log.info(f"Building partitions...")
    partitions = []
    covered = set()

    entry_partition_discovered = False
    project_entry = cfg.get_node(cfg.project.entry)

    for node in G.nodes():
        if node in covered:
            continue
        
        # Find all nodes reachable from this node
        queue: collections.deque[angr.analyses.cfg.CFGNode] = collections.deque([node])
        partition = set()
        while len(queue) > 0:
            n = queue.popleft()
            if n in covered or n in partition:
                continue

            partition.add(n)
            covered.add(n)

            # Go through both outgoing and incoming edges to merge as many nodes as possible
            edges = itertools.chain(
                ((v, data) for (_, v, data) in  G.out_edges(n, data=True)),
                ((v, data) for (v, _, data) in  G.in_edges(n, data=True)),
            )

            for (v, data) in edges:
                # Don't merge nodes if they're the source/destination of a syscall
                merge = True

                check_edges = itertools.chain(
                    (data for (_, _, data) in  G.out_edges(v, data=True)),
                    (data for (_, _, data) in  G.in_edges(v, data=True)),
                )

                for data in check_edges:
                    if data["jumpkind"] == "Syscall":
                        merge = False
                        break

                if merge:
                    queue.append(v)
        
        if not entry_partition_discovered:
            if project_entry in partition:
                partitions.insert(0, partition)
                entry_partition_discovered = True
                continue

        partitions.append(partition)

    # Then build the SCG
    log.info(f"Building SCG...")
    scg = networkx.DiGraph()

    # Freeze each partition to make them hashable
    partitions = [frozenset(x) for x in partitions]
    # And keep track of a node -> partition mapping
    node_to_partition = {}

    # One node for each partition
    for (i, part) in enumerate(partitions):
        name = list(part)[0].name if len(part) == 1 else "Many"
        scg.add_node(i, label=f"{i}: {name}")

        for node in part:
            node_to_partition[node] = i

    covered = set()
    for (i, part) in enumerate(partitions):
        if i in covered:
            continue
        
        covered.add(part)

        # Then look for outgoing edges to other nodes
        for node in part:
            for (_, out_node, out_edge_data) in G.out_edges(node, data=True):
                if out_node in part:
                    continue

                edge_name = out_edge_data.get("syscall_name", out_edge_data["jumpkind"])
                scg.add_edge(
                    i, node_to_partition[out_node],
                    label = f"{edge_name}({node.name})",
                    syscall_name = out_edge_data.get("syscall_name", None)
                )

    # Clean up any isolated nodes
    for (i, _) in enumerate(partitions):
        if scg.in_degree(i) == 0 and scg.out_degree(i) == 0:
            scg.remove_node(i)

    log.info(f"SCG built, # of nodes: {len(scg.nodes())}. # of edges: {len(scg.edges())}")

    return scg

def redirect_syscall_edges(G):
    for node in G.nodes():
        edges = list(G.out_edges(node, data=True))
        edge_count = len(edges)

        for i in range(edge_count):
            (_, target_node, target_edge_data) = edges[i]

            jumpkind = target_edge_data["jumpkind"]
            if jumpkind == "Ijk_Sys_syscall":
                # Make sure we don't accidentally clobber more fakerets, done by changing the jumpkind
                # Edit the jumpkind now to make sure we also edit syscalls with no remaining path
                target_edge_data["jumpkind"] = f"Syscall"
                target_edge_data["syscall_name"] = target_node.name

                # We're at the end of this node's edges, there are no more fakerets
                if i == edge_count - 1:
                    continue

                (_, fallthrough_node, fallthrough_data) = edges[i + 1]
                if fallthrough_data["jumpkind"] != "Ijk_FakeRet":
                    print(f"Non-fakeret edge found after syscall? {fallthrough_data}")
                    continue

                G.remove_edge(node, target_node)
                networkx.set_edge_attributes(G, {
                    (node, fallthrough_node): target_edge_data
                })

def clobber_call_fakeret_edges(G):
    for node in G.nodes():
        edges = list(G.out_edges(node, data=True))
        edge_count = len(edges)

        for i in range(edge_count):
            (_, _, target_edge_data) = edges[i]

            jumpkind = target_edge_data["jumpkind"]
            if jumpkind == "Ijk_Call":
                # Clobber the immediate next FakeRet if one exists
                if i == edge_count - 1:
                    continue

                (_, fallthrough_node, fallthrough_data) = edges[i + 1]
                if fallthrough_data["jumpkind"] != "Ijk_FakeRet":
                    print(f"Non-fakeret edge found after call? {fallthrough_data}")
                    continue

                G.remove_edge(node, fallthrough_node)
