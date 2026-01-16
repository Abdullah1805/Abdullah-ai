import networkx as nx

class AttackGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_edge(self, src, dst, technique):
        self.graph.add_edge(src, dst, technique=technique)

    def find_paths(self, sources, targets, max_depth=5):
        paths = []
        for s in sources:
            for t in targets:
                for path in nx.all_simple_paths(
                    self.graph, s, t, cutoff=max_depth
                ):
                    paths.append(path)
        return paths
