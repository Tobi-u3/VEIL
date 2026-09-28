"""Recent packet browsing and address-only topology. No DNS/GeoIP lookups."""
import ipaddress,os
from collections import deque
from functools import lru_cache

@lru_cache(maxsize=10000)
def address_info(value):
    ip=ipaddress.ip_address(value)
    docs=[ipaddress.ip_network(x) for x in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','2001:db8::/32')]
    if any(ip.version==n.version and ip in n for n in docs):scope='documentation'
    elif ip.is_loopback:scope='loopback'
    elif ip.is_link_local:scope='link-local'
    elif ip.is_multicast:scope='multicast'
    elif ip.is_global:scope='public'
    elif ip.is_private:scope='private'
    else:scope='reserved'
    return {'scope':scope,'ip_version':ip.version,
            'prefix':str(ipaddress.ip_network(f'{ip}/{int(os.getenv('VEIL_IPV4_PREFIX','24')) if ip.version==4 else int(os.getenv('VEIL_IPV6_PREFIX','64'))}',strict=False))}

class Traffic:
    def __init__(self,capacity=10000):
        self.packets=deque(maxlen=capacity);self.count=0;self.bytes=0
        self.capacity=capacity;self.last_ts=0
        self.graph_drops=0;self.edge_capacity=10000
        self.next_prune=0

    def add(self,e,graph):
        self.count+=1;self.bytes+=e.get('length',0);self.last_ts=max(self.last_ts,e['ts'])
        src_info=address_info(e['src'])
        packet={'sequence':self.count,'timestamp':e['ts'],'src':e['src'],'dst':e['dst'],
                'sport':e.get('sport',0),'dport':e.get('dport',0),'protocol':e.get('proto','unknown'),
                'length':e.get('length',0),'uid':e['uid'],'tcp_flags':e.get('tcp_flags'),
                'syn':bool(e.get('syn')),'source':e.get('source','live'),**src_info}
        self.packets.appendleft(packet)
        if e['ts']>=self.next_prune:
            for a,b,d in list(graph.edges(data=True)):
                if e['ts']-d['last']>120:graph.remove_edge(a,b)
            graph.remove_nodes_from(list(__import__('networkx').isolates(graph)))
            self.next_prune=e['ts']+5
        src,dst=e['src'],e['dst']
        if not graph.has_edge(src,dst):
            if graph.number_of_edges()>=self.edge_capacity:
                self.graph_drops+=1;return
            graph.add_edge(src,dst,packets=0,bytes=0,first=e['ts'],last=e['ts'],port_counts={},ports_truncated=False)
        edge=graph[src][dst];edge['packets']+=1;edge['bytes']+=packet['length'];edge['last']=e['ts']
        port_key=f"{e.get('proto','unknown')}:{e.get('dport',0)}"
        counts=edge.setdefault('port_counts',{})
        if port_key in counts or len(counts)<64:counts[port_key]=counts.get(port_key,0)+1
        else:edge['ports_truncated']=True

    def page(self,before=None,limit=100,query='',scope='all'):
        limit=max(1,min(limit,200));query=query.casefold().strip()
        def matches(p):
            return (scope=='all' or p['scope']==scope) and (not query or query in f"{p['src']} {p['dst']} {p['protocol']} {p['sport']} {p['dport']}".casefold())
        rows=[p for p in self.packets if (before is None or p['sequence']<before) and matches(p)]
        page=rows[:limit]
        return {'items':page,'next_before':page[-1]['sequence'] if len(rows)>limit else None,
                'retained':len(self.packets),'capacity':self.capacity,'total_captured':self.count,
                'oldest_sequence':self.packets[-1]['sequence'] if self.packets else None,
                'newest_sequence':self.count,'expired':max(0,self.count-len(self.packets))}

    def topology(self,graph,alerts,now):
        """Derive red edges AND node alert IDs from the very same retained feed."""
        edges={}
        for src,dst,d in graph.edges(data=True):
            if now-d['last']<=120:
                edges[(src,dst)]={'id':src+'|'+dst,'source':src,'target':dst,**d,'recent':True,'alert_ids':[]}
                edge=edges[(src,dst)]
                counts=edge.pop('port_counts',{})
                edge['ports']=[{'protocol':k.rsplit(':',1)[0],'port':int(k.rsplit(':',1)[1]),'packets':v} for k,v in sorted(counts.items(),key=lambda kv:(-kv[1],kv[0]))]
        for a in alerts:
            sources=a.get('related_sources') or [a['src']]
            for src in sources:
                try:ipaddress.ip_address(src)
                except ValueError:continue
                key=(src,a['dst'])
                if key not in edges:
                    edges[key]={'id':src+'|'+a['dst'],'source':src,'target':a['dst'],'packets':0,'bytes':0,
                                'first':None,'last':a['timestamp'],'recent':False,'alert_ids':[]}
                edges[key]['alert_ids'].append(a['id'])
        nodes={}
        for edge in edges.values():
            edge['suspicious']=bool(edge['alert_ids'])
            for ip,role in ((edge['source'],'source'),(edge['target'],'destination')):
                n=nodes.setdefault(ip,{'id':ip,**address_info(ip),'roles':set(),'alert_ids':set(),
                                    'packets':0,'bytes':0,'last_seen':0,'peers':set(),'recent':False})
                n['roles'].add(role);n['alert_ids'].update(edge['alert_ids']);n['packets']+=edge['packets'];n['bytes']+=edge['bytes']
                n['last_seen']=max(n['last_seen'],edge['last']);n['recent']|=edge['recent']
                n['peers'].add(edge['target'] if role=='source' else edge['source'])
        for n in nodes.values():
            n['roles']=sorted(n['roles']);n['alert_ids']=sorted(n['alert_ids']);n['peers']=sorted(n['peers'])
        return {'nodes':list(nodes.values()),'edges':list(edges.values()),'recent_seconds':120,
                'linked_alerts':len({i for e in edges.values() for i in e['alert_ids']}),
                'capacity':self.edge_capacity,'capacity_drops':self.graph_drops,
                'scope':'Recent observed contacts plus relationships for every retained detection'}
