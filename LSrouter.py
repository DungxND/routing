####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

from router import Router
import json
from packet import Packet
import networkx as nx

class LSrouter(Router):
    """Link state routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_heartbeat_time = 0
        self.my_seq_num = 0  # seq num this router
        self.my_links = {}  # direct link to neighbor
        self.ports_to_neighbors = {}  # ports to neighbor addr
        self.lsdb = {  # LSDB
            self.addr: {
                'seq_num': self.my_seq_num,
                'links': {}
            }
        }
        self.forwarding_table = {}
        print(f"LSrouter {self.addr} init.")

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:  # Data packet
            dest_addr = packet.dst_addr
            if dest_addr == self.addr:
                return  # Packet for current router

            if dest_addr in self.forwarding_table:
                self.send(self.forwarding_table[dest_addr], packet)
            # Drop if no route

        elif packet.kind == Packet.ROUTING:
            lsp_data = json.loads(packet.content)
            lsp_origin_addr = lsp_data.get('router_addr')
            lsp_seq_num = lsp_data.get('seq_num')
            lsp_links = lsp_data.get('links')

            # Check if seq num bigger than self lsdb to update
            current_seq_num = self.lsdb.get(lsp_origin_addr, {}).get('seq_num', -1)
            if lsp_seq_num > current_seq_num:
                self.lsdb[lsp_origin_addr] = {
                    'seq_num': lsp_seq_num,
                    'links': lsp_links.copy()
                }
                # Update route
                self._run_dijkstra()

                # Flood neighbors
                for neighbor_port in self.ports_to_neighbors:
                    if neighbor_port != port:
                        self.send(neighbor_port, packet)
            pass


    def _create_and_flood_lsp(self):
        """Create and flood LSP to all neighbors."""
        lsp_content = json.dumps({
            'router_addr': self.addr,
            'seq_num': self.my_seq_num,
            'links': self.my_links.copy()
        })

        for port, neighbor in self.ports_to_neighbors.items():
            lsp_packet = Packet(Packet.ROUTING, self.addr, neighbor, lsp_content)
            self.send(port, lsp_packet)


    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        print(f"{self.addr}: New link {endpoint}, port {port}, cost {cost}")

        # Update data
        self.my_links[endpoint] = cost
        self.ports_to_neighbors[port] = endpoint

        # Update lsdb
        self.my_seq_num += 1
        self.lsdb[self.addr] = {
            'seq_num': self.my_seq_num,
            'links': self.my_links.copy()
        }

        self._create_and_flood_lsp()

        # Update forw table
        self._run_dijkstra()
        print(f"{self.addr} table updated after new link")


    def handle_remove_link(self, port):
        """Handle removed link."""

        removed_neighbor = self.ports_to_neighbors[port]

        # Update data
        if removed_neighbor in self.my_links:
            del self.my_links[removed_neighbor]
        del self.ports_to_neighbors[port]

        # update lsdb
        self.my_seq_num += 1
        self.lsdb[self.addr] = {
            'seq_num': self.my_seq_num,
            'links': self.my_links.copy()
        }

        self._create_and_flood_lsp()

        self._run_dijkstra()
        print(f"{self.addr}: table updated after remove node")


    def handle_time(self, time_ms):
        """Send periodic LSP updates."""
        if time_ms - self.last_heartbeat_time >= self.heartbeat_time:
            self.last_heartbeat_time = time_ms

            self.my_seq_num += 1
            self.lsdb[self.addr] = {
                'seq_num': self.my_seq_num,
                'links': self.my_links.copy()
            }

            self._create_and_flood_lsp()

    def _run_dijkstra(self):
        """Run Dijkstra algorithm to update the forwarding table."""
        # Create graph
        graph = nx.Graph()
        all_nodes = set()

        # Collect all nodes from lsdb
        for router_addr, data in self.lsdb.items():
            all_nodes.add(router_addr)
            all_nodes.update(data['links'].keys())

        # Add nodes to graph
        graph.add_nodes_from(all_nodes)

        for router_addr, data in self.lsdb.items():
            for neighbor, cost in data['links'].items():
                graph.add_edge(router_addr, neighbor, weight=cost)

        # Check if router exist in graph
        if self.addr not in graph:
            self.forwarding_table = {}
            print(f"{self.addr}: Not in graph, table cleared.")
            return

        # Create port lookup for neighbors
        neighbor_to_port = {neighbor: port for port, neighbor in self.ports_to_neighbors.items()}

        # Compute shortest paths
        _, paths = nx.single_source_dijkstra(graph, self.addr, weight='weight')

        # new forw table
        new_forwarding_table = {}
        for dest, path in paths.items():
            if dest != self.addr and len(path) > 1:
                next_hop = path[1]  # First hop in path
                if next_hop in neighbor_to_port:
                    new_forwarding_table[dest] = neighbor_to_port[next_hop]

        self.forwarding_table = new_forwarding_table
        print(f"{self.addr}: Forwarding table updated Dijk: {self.forwarding_table}")
