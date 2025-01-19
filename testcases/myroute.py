class ForwardingTableEntry:
    def __init__(self, dest, mask, gateway, interface):
        self.dest = dest
        self.mask = mask
        self.gateway = gateway
        self.interface = interface
        self.prefixnet = IPv4Network(f"{dest}/{mask}", strict=False)
#prefixnet 表示网络对象
#当strict设置为False时，允许网络地址中的主机部分不为零。也就是说，即#使IP地址不是该网络的真正起始地址，也可以创建一个有效的网络对象。
    def __lt__(self, other):
        return self.prefixnet.prefixlen > other.prefixnet.prefixlen
		#重定义类的排序，用前缀长度进行排序。用于后面的sort函数中。


class Router:
    def __init__(self, net):
        self.net = net
        self.interfaces = self.net.interfaces()
        self.arp_table = {}
        self.ip_list = [interface.ipaddr for interface in self.interfaces]
        self.forwarding_table = []
        # 初始化转发表项
        for interface in self.interfaces:
            self.forwarding_table.append(ForwardingTableEntry(interface.ipaddr, interface.netmask, None, interface.name))
        # 尝试从文件加载转发表项
        try:
            with open("forwarding_table.txt", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) == 4:
                        dest, mask, gateway, interface = parts
                        self.forwarding_table.append(ForwardingTableEntry(dest, mask, gateway, interface))
        except FileNotFoundError:
            pass
        # 按照前缀长度降序排序转发表
        self.forwarding_table.sort()
        self.waiting_packet = {}
        self.waiting_ip = {}

    def get_forwarding_entry(self, ipaddr):
        for entry in self.forwarding_table:
            if ipaddr in entry.prefixnet:
                return entry
        return None
#在路由器的转发表（forwarding_table）中查找与给定 IP 地址（ipaddr）匹
#配的路由条目
    def handle_ipv4_packet(self, recv):
        timestamp, ifaceName, packet = recv
        ipv4 = packet.get_header(IPv4)
        eth = packet.get_header(Ethernet)
        dst_ip = ipv4.dst
        # 检查数据包长度是否合法
        if len(eth) + ipv4.total_length!= packet.size():
            return
        # 如果目的IP是本地接口IP则不处理
        if dst_ip in self.ip_list:
            return
        entry = self.get_forwarding_entry(dst_ip)
        if entry is None:
            return
		#如果 get_forwarding_entry 方法没有找到匹配的路由表项，它会返回 None
	#如果 entry 是 None，说明路由器不知道如何转发这个数据包到目的IP地
#址。在这种情况下，函数通过 return 语句提前退出，不再进行后续的转发
        next_hop_ip = ip_address(entry.gateway) if entry.gateway else dst_ip
        next_hop_mac = self.arp_table.get(next_hop_ip)

        if next_hop_mac:
            # 构建转发数据包
            packet[Ethernet].src = self.net.interface_by_name(entry.interface).ethaddr
            packet[Ethernet].dst = next_hop_mac
            packet[IPv4].ttl -= 1
            self.net.send_packet(entry.interface, packet)
        else:
            # 处理缓存未命中情况
            if next_hop_ip not in self.waiting_ip:
                self.waiting_ip[next_hop_ip] = (time.time(), 1)
#记录当前时间 time.time() 和计数 1，用于后续的超时处理和重试机#制
                arp_request = create_ip_arp_request(
                    self.net.interface_by_name(entry.interface).ethaddr,
                    self.net.interface_by_name(entry.interface).ipaddr, next_hop_ip)
				#create_ip_arp_request 函数用于创建一个ARP请求数据包。
#参数分别是发送ARP请求的接口的MAC地址、IP地址和目标下一#跳的IP地址
                self.net.send_packet(entry.interface, arp_request)
				#发送arp请求
            if next_hop_ip not in self.waiting_packet:
                self.waiting_packet[next_hop_ip] = []
				#如果 next_hop_ip 不在 self.waiting_packet 中，则初始化一个空列表
            self.waiting_packet[next_hop_ip].append(packet)
			#将当前数据包 packet 添加到对应下一跳IP地址的等待列表中
    def handle_arp_packet(self, recv):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        eth = packet.get_header(Ethernet)
        src_ip = arp.senderprotoaddr
        src_mac = arp.senderhwaddr
        dst_ip = arp.targetprotoaddr
        if dst_ip not in self.ip_list:
            return
        if arp.operation == ArpOperation.Request: #如果是arp请求
            self.arp_table[src_ip] = src_mac	#将发送ARP请求的设备的IP地址（src_ip）和MAC地址（src_mac）添加到或更新到ARP缓存表（self.arp_table）中
            arp_reply = create_ip_arp_reply(	#创建一个ARP回复数据包。
                self.net.interface_by_ipaddr(dst_ip).ethaddr, src_mac, dst_ip, src_ip)
            self.net.send_packet(ifaceName, arp_reply)
			# self.net.interface_by_ipaddr(dst_ip).ethaddr：获取目标IP地址
（dst_ip）对应的接口的MAC地址
			# self.net.send_packet(ifaceName, arp_reply)：通过指定的接口（ifaceName）发送创建的ARP回复数据包
        elif arp.operation == ArpOperation.Reply:
            if eth.src == 'ff:ff:ff:ff:ff:ff':
                return	 #检查以太网帧的源MAC地址是否为广播地址
#（ff:ff:ff:ff:ff:ff）。如果是广播地址，则不进行处理并直接返回。
            self.arp_table[src_ip] = src_mac 
#将发送ARP回复的设备的IP地址（src_ip）和MAC地址（src_mac）添#加到或更新到ARP缓存表（self.arp_table）中。
            if src_ip in self.waiting_ip:
                for packet in self.waiting_packet[src_ip]:
                    packet[Ethernet].src = self.net.interface_by_name(ifaceName).ethaddr
			#将数据包的源MAC地址修改为当前网络接口的MAC地址
                    packet[Ethernet].dst = src_mac
			#将数据包的目的MAC地址修改为 src_mac，即源IP对应的MAC地址
                    packet[IPv4].ttl -= 1
			#ttl-1，用于超时处理
                    self.net.send_packet(ifaceName, packet)
			#发包
                del self.waiting_packet[src_ip]
                del self.waiting_ip[src_ip]
			#删除 self.waiting_packet 和 self.waiting_ip 中对应的 src_ip 条目，表示这些数据包已经处理完毕，不再需要等待响应
    def handle_timeout(self):
        current_time = time.time()
		#记录当前时间戳
        to_delete_ips = []
		#创建一个空列表 to_delete_ips，用于存储需要删除的 IP 地址
        for ip, (timestamp, retries) in self.waiting_ip.items():
            if current_time - timestamp > 1:
#如果当前时间减去记录的时间戳大于 1 秒，则认为该 IP 的 ARP 请求#超时
                if retries >= 5:
                    to_delete_ips.append(ip)
#如果重试次数大于等于5次，则将该IP添加到 to_delete_ips 列
#表中，准备删除
                else:
                    self.waiting_ip[ip] = (current_time, retries + 1)
                    entry = self.get_forwarding_entry(ip)
                    if entry:
                        arp_request = create_ip_arp_request(
                            self.net.interface_by_name(entry.interface).ethaddr,
                            self.net.interface_by_name(entry.interface).ipaddr, ip)
                        self.net.send_packet(entry.interface, arp_request)
#如果重试次数小于5次，则更新时间戳和重试次数，并尝试重新
#发送ARP请求
        for ip in to_delete_ips:
            del self.waiting_ip[ip]
            del self.waiting_packet[ip]
		#删除超时的IP
    def handle_packet(self, recv):
        timestamp, ifaceName, packet = recv
        eth = packet.get_header(Ethernet)
        # 只处理发往本接口或者广播的数据包
        if eth.dst!= self.net.interface_by_name(ifaceName).ethaddr and eth.dst!= 'ff:ff:ff:ff:ff:ff':
            return
		#如果数据包的目标MAC地址既不是当前网络接口的MAC地址，也不是广播地址，则直接返回，不进行后续处理
        if eth.ethertype == EtherType.ARP:
            self.handle_arp_packet(recv)
        elif eth.ethertype == EtherType.IPv4:
            ipv4 = packet.get_header(IPv4)
            self.handle_ipv4_packet(recv)
#检查以太网帧类型，分ipv4和arp进行处理。eth.ethertype 是以太网帧的类#型字段。EtherType.ARP 表示ARP协议。EtherType.IPv4 表示IPv4协议。



