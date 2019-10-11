/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */
// How do we close a listening socket with pending connections?
// Accept is a blocked call. So, it doesn't return until it really establishes connection
// Thus, listening socket must not have pending connections at the time close is called
// However, it might have waiting connections. Do we send FIN packets to all clients?


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/E_TimeUtil.hpp>
#include "TCPAssignment.hpp"
#include <typeinfo>

namespace E
{
uint16_t FIN_FLAG = 0x0001;
uint16_t SYN_FLAG = 0x0002;
uint16_t ACK_FLAG = 0x0010;
uint16_t BUFFER_SIZE = 51200;
uint32_t TIMEOUT = 100000000;
uint16_t MAX_PACKET_SIZE = 512;

//std::map<pid_fd, Socket> sockets;

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	sockets.clear();
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, const int family, const int protocol){
	int fd = createFileDescriptor(pid);
	if (fd < 0){
		returnSystemCall(syscallUUID, -1);
		return;
	}
	pid_fd key;
	key.first = pid;
	key.second = fd;

	Socket sock;
	sockets[key] = sock;
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, const int fd){
	pid_fd key;
	key.first = pid;
	key.second = fd;
	auto it = sockets.find(key);
	if (it == sockets.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}
	Socket *s = &it->second;
	if (!s->bound || s->state == CLOSED || s->state == SYNSENT){
		// connect call is blocked until established. Theoretically,
		// it is impossible for close to be called on SYNSENT socket.
		// Just in case.
		sockets.erase(key);
		removeFileDescriptor(pid, fd);
		returnSystemCall(syscallUUID, 0);
		return;
	}
	if (s->state == ESTAB && empty_space(s) < BUFFER_SIZE){
		// still has some data to send
		s->closing = true;
		returnSystemCall(syscallUUID, 0);
		return;
	}
	if (s->state == ESTAB){
		// send FIN packet and go to FIN_WAIT_1 state

		uint16_t offset_and_flags = 0x5;
		offset_and_flags<<=12;
		offset_and_flags|=FIN_FLAG;

		Packet *packet = this->allocatePacket(14 + 12 + 8 + 20);
		fill_packet(packet, s->local_ip, s->local_port, s->remote_ip, s->remote_port,s->seq_num, 0, offset_and_flags, BUFFER_SIZE - recv_buf_size(s));
		s->increment_seq_num();
		this->sendPacket("IPv4", packet);

		s->set_state(FIN_WAIT_1);
		s->last_ack_expected = s->seq_num;

		char *pload = (char *) malloc(1 + sizeof(pid_fd));
		memset(pload, 5, 1);
		memcpy(pload + 1, &it->first, sizeof(pid_fd));
		s->close_timer = addTimer(pload, TIMEOUT);

		returnSystemCall(syscallUUID, 0);
		return;
	}

	if (s->state == CLOSE_WAIT){
		// send FIN packet
		// Should have already sent ACK for FIN at this point

		uint16_t offset_and_flags = 0x5;
		offset_and_flags<<=12;
		offset_and_flags|=FIN_FLAG;

		Packet *packet = this->allocatePacket(14 + 12 + 8 + 20);
		fill_packet(packet, s->local_ip, s->local_port, s->remote_ip, s->remote_port, s->seq_num, 0, offset_and_flags, BUFFER_SIZE - recv_buf_size(s));
		s->increment_seq_num();
		this->sendPacket("IPv4", packet);

		s->set_state(LAST_ACK);
		s->last_ack_expected = s->seq_num;

		char *pload = (char *) malloc(1 + sizeof(pid_fd));
		memset(pload, 5, 1);
		memcpy(pload + 1, &it->first, sizeof(pid_fd));
		s->close_timer = addTimer(pload, TIMEOUT);

		returnSystemCall(syscallUUID, 0);
		return;
	}
	if (s->state == PASSIVE){
		// TODO: Listening socket; Close all waiting connections
		if (s->listen->pending_list != NULL){
			std::cout << "pending_list: Should not happen\n";
		}
		if (s->listen->waiting_list != NULL){
			std::cout << "waiting_list: Should not happen\n";
		}
		free(s->listen);
		sockets.erase(key);
		removeFileDescriptor(pid, fd);
		returnSystemCall(syscallUUID, 0);
		return;
		
	}
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t len){
	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	uint32_t ip = ntohl(addr_in->sin_addr.s_addr);
	uint16_t port = ntohs(addr_in->sin_port);
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		// such socket is not opened
		//std::cout << "bind: " << pid << " " << fd << " not open\n";
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *s = &(it->second);
	if (s->bound){
		// given socket is already bound
		returnSystemCall(syscallUUID, -1);
		return;
	}

	// check if other sockets have same ip:port or port is already used by INADDR_ANY
	for (auto p = sockets.begin(); p != sockets.end(); p++){
		if (p->second.bound && p->second.local_port == port 
					&& (p->second.local_ip == ip || p->second.local_ip == INADDR_ANY || ip == INADDR_ANY)){
			// std::cout << "bind: port " << port << " taken\n";
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}
	s->set_bound(true);
	s->set_local_hp(ip, port);
	returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t len){
	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	uint32_t ip = ntohl(addr_in->sin_addr.s_addr);
	uint16_t port = ntohs(addr_in->sin_port);
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		// such socket is not opened
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *s = &(it->second);
	if (!s->bound){
		// do implicit bind
		uint32_t ip_buf = htonl(ip);
		Host *h = getHost();
		int routing_port = h->getRoutingTable((uint8_t *) &ip_buf);
		h->getIPAddr((uint8_t *) &ip_buf, routing_port);

		// get which ports are occupied
		char is_occupied[65536];
		for (auto p = sockets.begin(); p != sockets.end(); p++){
			if (p->second.bound && (p->second.local_ip == INADDR_ANY || p->second.local_ip == ip))
				is_occupied[p->second.local_port] = 1;
		}

		// ports 0 to 1024 are reserved. So get first free port after 1024
		uint16_t random_port = 0;
		for (int i = 1025; i < 65536; i++){
			if (!is_occupied[i]){
				random_port = (uint16_t) i;
				break;
			}
		}

		if (!random_port){
			// all ports were occupied!
			returnSystemCall(syscallUUID, -1);
			return;
		}

		s->set_bound(true);
		s->set_local_hp(ntohl(ip_buf), random_port);
	}

	s->set_remote_hp(ip, port);
	//std::cout << "local_port is " << s->local_port << "\n";
	//std::cout << "remote_port is " << s->remote_port << "\n";
	s->set_syscallUUID(syscallUUID);
	s->set_state(SYNSENT);

	uint16_t offset_and_flags = 0x5;
	offset_and_flags<<=12;
	offset_and_flags|=SYN_FLAG;

	Packet *packet = this->allocatePacket(14 + 12 + 8 + 20);
	fill_packet(packet, s->local_ip, s->local_port, ip, port, s->seq_num, 0, offset_and_flags, BUFFER_SIZE - recv_buf_size(s));
	s->increment_seq_num();
	this->sendPacket("IPv4", packet);

	char *payload = (char *) malloc(1 + sizeof(pid_fd));
	memset(payload, 3, 1);
	memcpy(payload + 1, &key, sizeof(pid_fd));
	s->timer = addTimer((void *) payload, TIMEOUT);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		// such socket is not opened
		// std::cout << "listen: such socket is not opened\n";
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket *s = &(it->second);
	s->listen = (struct listening *) calloc(1, sizeof(struct listening));
	if (!s->listen){
		//std::cout << "listen: calloc error\n";
		returnSystemCall(syscallUUID, -1);
		return;
	}
	s->listen->backlog = backlog;
	s->listen->pending_count = 0;
	s->listen->waiting_count = 0;
	s->set_state(PASSIVE);
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t *len){
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		// such socket is not opened
		returnSystemCall(syscallUUID, -1);
		return;
	}
	Socket *s = &(it->second);
	if (s->state!=PASSIVE){
		// should not happen
		//std::cout << "Accept: socket is not a listening socket\n\n";
		returnSystemCall(syscallUUID, -1);
		return;
	}
	
	if (s->listen->waiting_count > 0){
		// sockets waiting to be accepted
		int new_fd = createFileDescriptor(pid);
		if (new_fd < 0) 
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}

		pid_fd new_key;
		new_key.first = pid;
		new_key.second = new_fd;

		struct hp_list *entry = s->listen->waiting_list;
		uint32_t dest_ip = entry->ip;
		uint16_t dest_port = entry->port;
		(s->listen->waiting_count)--;
		s->listen->waiting_list = s->listen->waiting_list->next;

		Socket new_s;
		new_s.set_bound(true);
		new_s.set_local_hp(entry->local_ip, s->local_port);
		new_s.set_has_connection(true);
		new_s.set_remote_hp(dest_ip, dest_port);
		new_s.set_state(entry->state);
		new_s.set_ack_num(entry->ack_num);
		new_s.set_seq_num(entry->seq_num);
		new_s.set_peer_window_size(entry->window_size);
		new_s.last_ack = entry->seq_num;

		struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = htons(new_s.remote_port);
		addr_in->sin_addr.s_addr = htonl(new_s.remote_ip);
		*len = sizeof(struct sockaddr_in);

		free(entry);
		sockets[new_key] = new_s;
		returnSystemCall(syscallUUID, new_fd);
		return;

	}
	s->listen->syscallUUID = syscallUUID;
	s->listen->addr = addr;
	s->listen->len = len;
	s->listen->pid = pid;
}


void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t *len)
{
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket s = it->second;
	if (!s.bound){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	memset(addr_in, 0, *len);
	addr_in->sin_addr.s_addr = htonl(s.local_ip);
	addr_in->sin_port = htons(s.local_port);
	addr_in->sin_family = AF_INET;

	*len = sizeof(struct sockaddr_in);
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *len)
{
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	Socket s = it->second;
	if (!s.bound || !s.has_connection){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	memset(addr_in, 0, *len);
	addr_in->sin_addr.s_addr = htonl(s.remote_ip);
	addr_in->sin_port = htons(s.remote_port);
	addr_in->sin_family = AF_INET;

	*len = sizeof(struct sockaddr_in);
	returnSystemCall(syscallUUID, 0);
}

uint16_t TCPAssignment::empty_space(Socket *s){
	//std::cout << "empty_space call\n";
	struct data_list *temp;
	uint16_t free = BUFFER_SIZE;
	for(temp = s->send_q; temp != NULL; temp = temp->next){
		free-=(temp->size);
	}
	return free;
}

uint16_t TCPAssignment::recv_buf_size(Socket *s){
	//std::cout << "recv_buf_size call\n";
	struct data_list *temp;
	uint16_t taken = 0;
	for(temp = s->recv_q; temp != NULL; temp = temp->next){
		taken+=(temp->size - temp->already_read);
	}
	return taken;
}

void TCPAssignment::update_cwnd(Socket *s, int times){
	if (s->cong_state == SLOW_START){
		s->cwnd = s->cwnd + times*s->MSS;
		if (s->cwnd >= s->ssthresh)
			s->cong_state = CONGESTION_AVOIDANCE;
	}
	else if (s->cong_state == CONGESTION_AVOIDANCE){
		s->cwnd = s->cwnd + (uint32_t) ((double) s->MSS*((double) s->MSS / (double) s->cwnd));
	}
	else{
		s->cwnd = s->ssthresh;
		s->cong_state = CONGESTION_AVOIDANCE;
	}
}

void TCPAssignment::sendAll(Socket *s, bool isretransmit){
	uint8_t header[20];
	memset(header, 0, 20);

	uint32_t source_ip_net = htonl(s->local_ip);
	uint16_t source_port_net = htons(s->local_port);
	uint32_t dest_ip_net = htonl(s->remote_ip);
	uint16_t dest_port_net = htons(s->remote_port);

	uint32_t ack_num = htonl(s->ack_num);
	uint16_t offset_and_flags = 0x5;
	offset_and_flags<<=12;
	offset_and_flags|=ACK_FLAG;
	offset_and_flags = htons(offset_and_flags);
	uint16_t window = htons(BUFFER_SIZE - recv_buf_size(s));

	memcpy(header, &source_port_net, 2);
	memcpy(header + 2, &dest_port_net, 2);
	memcpy(header + 8, &ack_num, 4);
	memcpy(header + 12, &offset_and_flags, 2);
	memcpy(header + 14, &window, 2);

	uint16_t peer_window = s->peer_window_size;
	struct data_list *temp;
	for (temp = s->send_q; temp != NULL && temp->next != NULL; temp = temp->next){
		if (temp->sent)
			peer_window-=(temp->size);
	}
	if (temp != NULL && temp->sent)
		peer_window-=(temp->size);

	peer_window = std::min((uint32_t) peer_window, s->cwnd);
	//std::cout << "sendAll: starting from seq_num " << temp->seq_num << "\n";
	while(temp != NULL){
		//std::cout << "sendAll: seq_num " << temp->seq_num << "\n";
		if (temp->sent){
			temp = temp->prev;
			continue;
		}
		if (temp->size > peer_window)
			break;
		uint8_t tcp_seg[20 + temp->size];
		memcpy(tcp_seg, header, 20);
		uint32_t temp_seq_num = htonl(temp->seq_num);
		memcpy(tcp_seg + 4, &temp_seq_num, 4);
		memcpy(tcp_seg + 20, temp->payload, temp->size);

		uint16_t checksum = htons(~NetworkUtil::tcp_sum(source_ip_net, dest_ip_net, tcp_seg, 20 + temp->size));
		memcpy(tcp_seg + 16, &checksum, 2);

		Packet *packet = this->allocatePacket(54 + temp->size);
		packet->writeData(14 + 4*3, &source_ip_net, 4);
		packet->writeData(14 + 4*4, &dest_ip_net, 4);
		packet->writeData(14 + 20, tcp_seg, 20 + temp->size);
		this->sendPacket("IPv4", packet);

		temp->sent = true;
		temp->time = this->getHost()->getSystem()->getCurrentTime();
		peer_window-=temp->size;
		if (peer_window == 0)
			break;
		if (isretransmit)
			break;
		temp = temp->prev;
	}

	if (!s->timer_set && peer_window < s->peer_window_size)
	{
		//std::cout << "sendAll: setting timer\n";
		char *key = (char *) malloc(1 + sizeof(s));
		memset(key, 2, 1);
		memcpy(key + 1, &s, sizeof(s));
		s->timer = addTimer((void *) key, 80000000);
		s->timer_set = true;
	}
}

void  TCPAssignment::unsend(Socket *s){
	//std::cout << "unsend call\n";
	struct data_list *temp;
	for(temp = s->send_q; temp != NULL; temp = temp->next){
		temp->sent = false;
	}
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int count)
{
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if (count == 0){
		returnSystemCall(syscallUUID, 0);
		return;
	}
	Socket *s = &(it->second);
	uint16_t free_space = empty_space(s);
	// std::cout << "free space = " << free_space << "\n";
	if (free_space >= count){
		uint16_t remaining = count;
		uint16_t start = 0;
		uint16_t size;
		char *b = (char *) buf;
		while (remaining > 0){
			size = std::min(MAX_PACKET_SIZE, remaining); 
			struct data_list *node = (struct data_list *) malloc(sizeof(struct data_list));
			if (node == NULL){
				//std::cout << "write: error1\n";
				returnSystemCall(syscallUUID, -1);
				return;
			}
			node->size = size;
			node->seq_num = s->seq_num;
			//std::cout << "write: " << start << " " << size << " " << remaining << " " << node->seq_num << " d\n";
			node->sent = false;
			s->seq_num+=size;
			node->payload = (char *) malloc(size);
			if (node->payload == NULL){
				//std::cout << "write: error2\n";
				returnSystemCall(syscallUUID, -1);
				return;
			}
			memcpy(node->payload, b + start, size);

			node->next = NULL;
			node->prev = NULL;

			node->next = s->send_q;
			if (s->send_q != NULL)
				s->send_q->prev = node;
			node->prev = NULL;
			s->send_q = node;

			start+=size;
			remaining-=size;
		}
		returnSystemCall(syscallUUID, count);
	}
	else{
		//std::cout << "blocked\n";
		s->writing = true;
		s->buf = (char *) buf;
		s->syscallUUID = syscallUUID;
		s->count = count;
	}
	sendAll(s, false);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int count)
{
	pid_fd key;
	key.first = pid;
	key.second = fd;
	auto it = sockets.find(key);
	if (it == sockets.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if (count == 0){
		// TODO: maybe send a packet with zero payload?
		returnSystemCall(syscallUUID, -1);
		return;
	}
	Socket *s = &(it->second);
	uint16_t data_size = recv_buf_size(s);
	if (data_size > 0){
		struct data_list *temp;
		for (temp = s->recv_q; temp != NULL && temp->next != NULL; temp = temp->next){
			continue;
		}
		uint16_t size;
		uint16_t to_read;
		uint16_t remaining = count;
		uint16_t ans = 0;
		char *b = (char *) buf;
		while(temp != NULL){
			size = temp->size - temp->already_read;
			to_read = std::min(size, remaining);
			memcpy(b + (count - remaining), temp->payload + temp->already_read, to_read);
			temp->already_read+=to_read;
			ans+=to_read;
			remaining-=to_read;

			if (temp->already_read == temp->size){
				free(temp->payload);
				if (temp->next != NULL)
					temp->next->prev = temp->prev;
				if (temp->prev != NULL)
					temp->prev->next = temp->next;
				struct data_list *temp2 = temp;
				if (s->recv_q == temp)
					s->recv_q = s->recv_q->next;
				temp = temp->prev;
				free(temp2);
			}
			else
				break;
			if (remaining == 0)
				break;
		}
		if (count > 0 && ans == 0)
			returnSystemCall(syscallUUID, -1);
		else
			returnSystemCall(syscallUUID, ans);
		return;
	}
	// && s->ack_num == s->last_seq_num_expected
	else if (s->state == CLOSE_WAIT && s->ack_num == s->last_seq_num_expected){
		returnSystemCall(syscallUUID, -1);
		return;
	}
	else{
		s->reading = true;
		s->buf = (char *) buf;
		s->syscallUUID = syscallUUID;
		s->count = count;
	}
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint32_t source_ip_net;
	uint16_t source_port_net;
	uint32_t dest_ip_net;
	uint16_t dest_port_net;
	packet->readData(14 + 12, &source_ip_net, 4); 
	packet->readData(14 + 16, &dest_ip_net, 4);
	packet->readData(14 + 20, &source_port_net, 2);
	packet->readData(14 + 20 + 2, &dest_port_net, 2);
	uint32_t source_ip = ntohl(source_ip_net);
	uint16_t source_port = ntohs(source_port_net);
	uint32_t dest_ip = ntohl(dest_ip_net);
	uint16_t dest_port = ntohs(dest_port_net);

	uint16_t offset_and_flags;
	packet->readData(14 + 20 + 12, &offset_and_flags, 2);
	offset_and_flags = ntohs(offset_and_flags);

	//std::cout << "Packet arrived\n";
	size_t tcp_size = packet->getSize() - 14 - 20;
	uint8_t tcp_buf[tcp_size];
	packet->readData(14 + 20, tcp_buf, tcp_size);
	uint16_t checksum = htons(~NetworkUtil::tcp_sum(source_ip_net, dest_ip_net, tcp_buf, tcp_size));
	if (checksum != 0){
		// Incorrect checksum, just drop packet
		this->freePacket(packet);
		return;
	}

	if (offset_and_flags & SYN_FLAG){
		//std::cout << "SYN packet arrived\n";
		if (offset_and_flags & ACK_FLAG)
		{
			// Client received SYNACK
			//std::cout << "SYNACK from ip:port " << source_ip << "  " << source_port << "\n";
			for (auto it = sockets.begin(); it != sockets.end(); it++){
				Socket *s = &(it->second);
				//std::cout << "info " << s->state << " " << s->remote_ip << " " << s->remote_port << "\n";
				if (s->bound && s->state == SYNSENT 
							 && s->local_ip == dest_ip && s->local_port == dest_port
							 && s->remote_ip == source_ip && s->remote_port == source_port)
				{
					// TODO: Check if ACK from server is correct (equal to own seq_num)
					cancelTimer(s->timer);

					uint32_t received_ack_num;
					packet->readData(14 + 20 + 8, &received_ack_num, 4);
					received_ack_num = ntohl(received_ack_num);
					s->last_ack = received_ack_num;

					uint32_t ack_num;
					packet->readData(14 + 20 + 4, &ack_num, 4);
					ack_num = ntohl(ack_num);
					ack_num++;
					s->set_ack_num(ack_num);

					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;

					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, dest_ip, dest_port, source_ip, source_port, s->seq_num, s->ack_num, flags, BUFFER_SIZE);
					this->sendPacket("IPv4", response);

					uint16_t peer_window;
					packet->readData(14 + 20 + 14, &peer_window, 2);
					s->set_peer_window_size(ntohs(peer_window));
					this->freePacket(packet);

					s->set_has_connection(true);
					s->set_state(ESTAB);
					returnSystemCall(s->syscallUUID, 0);

					return;
				}
				if (s->bound  
							 && s->local_ip == dest_ip && s->local_port == dest_port
							 && s->remote_ip == source_ip && s->remote_port == source_port)
				{

					uint32_t received_ack;
					packet->readData(14 + 20 + 4, &received_ack, 4);
					received_ack = ntohl(received_ack);
					received_ack++;

					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;

					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, dest_ip, dest_port, source_ip, source_port, s->seq_num, received_ack, flags, BUFFER_SIZE);
					this->sendPacket("IPv4", response);
				}
			}
			this->freePacket(packet);
			return;
		}
		else
		{
			// server received SYN
			//std::cout << "SYN from ip:port " << source_ip << "  " << source_port << "\n";
			for (auto it = sockets.begin(); it != sockets.end(); it++){
				Socket *s = &(it->second);
				if (s->bound && s->state == PASSIVE
							 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)){
					if (s->listen->pending_count >= s->listen->backlog){
						// Ignore connection request
						this->freePacket(packet);
						return;
					}
					struct hp_list *temp;
					for (temp = s->listen->pending_list; temp != NULL; temp = temp->next){
						if (temp->ip == source_ip && temp->port == source_port){
							// already in pending list, just send SYNACK again
							cancelTimer(temp->timer);

							uint16_t flags = 0x0005;
							flags<<=12;
							flags|=ACK_FLAG;
							flags|=SYN_FLAG;

							Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
							fill_packet(response, dest_ip, dest_port, source_ip, source_port, temp->seq_num - 1, temp->ack_num, flags, BUFFER_SIZE);
							this->sendPacket("IPv4", response);
							this->freePacket(packet);

							char *payload = (char *) malloc(1 + sizeof(struct hp_list *));
							memset(payload, 4, 1);
							memcpy(payload + 1, &temp, sizeof(struct hp_list *));
							temp->timer = addTimer((void *) payload, TIMEOUT);
							return;
						}
					}

 					(s->listen->pending_count)++;
 					struct hp_list *node = (struct hp_list *) calloc(1, sizeof(struct hp_list));
 					if (node == NULL){
 						//std::cout << "Server received SYN: calloc error\n";
 						this->freePacket(packet);
 						return;
 					}
 					node->local_ip = dest_ip;
 					node->local_port = dest_port;
 					node->ip = source_ip;
 					node->port = source_port;
 					node->seq_num = s->seq_num;

 					uint32_t ack_num;
					packet->readData(14 + 20 + 4, &ack_num, 4);
					ack_num = ntohl(ack_num);
					ack_num++;
					node->ack_num = ack_num;

					uint16_t peer_window;
					packet->readData(14 + 20 + 14, &peer_window, 2);
					peer_window = ntohs(peer_window);
					node->window_size = peer_window;

					node->state = SYNRCVD;

 					node->next = s->listen->pending_list;
 					s->listen->pending_list = node;


					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;
					flags|=SYN_FLAG;

					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, dest_ip, dest_port, source_ip, source_port, node->seq_num, node->ack_num, flags, BUFFER_SIZE);
					node->seq_num++;
					this->sendPacket("IPv4", response);

					char *payload = (char *) malloc(1 + sizeof(struct hp_list *));
					memset(payload, 4, 1);
					memcpy(payload + 1, &node, sizeof(struct hp_list *));
					node->timer = addTimer((void *) payload, TIMEOUT);

					this->freePacket(packet);
					return;
				}
			}
			this->freePacket(packet);
			return;
		}
	}

	if (offset_and_flags & FIN_FLAG){
		//std::cout << "FIN packet arrived\n";
		for (auto it = sockets.begin(); it != sockets.end(); it++){
			Socket *s = &(it->second);
			if (s->bound && s->state == ESTAB
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				uint32_t received_seq_num;
				packet->readData(14 + 20 + 4, &received_seq_num, 4);
				received_seq_num = ntohl(received_seq_num);
				s->last_seq_num_expected = received_seq_num;
				
				uint16_t flags = 0x0005;
				flags<<=12;
				flags|=ACK_FLAG;

				if (s->ack_num == received_seq_num){
					s->ack_num++;
					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, s->local_ip, dest_port, s->remote_ip, source_port, s->seq_num, s->last_seq_num_expected + 1, flags, BUFFER_SIZE - recv_buf_size(s));
					this->sendPacket("IPv4", response);
					this->freePacket(packet);
				}

				s->set_state(CLOSE_WAIT);
				s->closing = true;
				/*
				if (s->reading){
					s->reading = false;
					returnSystemCall(s->syscallUUID, -1);
				}
				*/
				return;
			}
			if (s->bound && (s->state == FIN_WAIT_1 || s->state == FIN_WAIT_2)
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				uint32_t ack_num;
				packet->readData(14 + 20 + 4, &ack_num, 4);
				ack_num = ntohl(ack_num);
				ack_num++;
				s->set_ack_num(ack_num);

				uint16_t flags = 0x0005;
				flags<<=12;
				flags|=ACK_FLAG;

				Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
				fill_packet(response, s->local_ip, dest_port, s->remote_ip, source_port, s->seq_num, s->ack_num, flags, BUFFER_SIZE);
				this->sendPacket("IPv4", response);
				this->freePacket(packet);

				if (offset_and_flags & ACK_FLAG){
					//assert(s->state == FIN_WAIT_1);
					s->set_state(TIME_WAIT);

					char *pload = (char *) malloc(1 + sizeof(pid_fd));
					memset(pload, 1, 1);
					memcpy(pload + 1, &(it->first), sizeof(pid_fd));
					Time time = TimeUtil::makeTime(2, TimeUtil::stringToTimeUnit("MINUTE"));
					//Time time = 2L * 60L*1000L*1000L*1000L;
					addTimer((void *) pload, time);
					return;
				}
				else if (s->state == FIN_WAIT_2){
					s->set_state(TIME_WAIT);

					char *pload = (char *) malloc(1 + sizeof(pid_fd));
					memset(pload, 1, 1);
					memcpy(pload + 1, &(it->first), sizeof(pid_fd));
					Time time = TimeUtil::makeTime(2, TimeUtil::stringToTimeUnit("MINUTE"));
					//Time time = 2L * 60L*1000L*1000L*1000L;
					addTimer((void *) pload, time);
					return;
				}
				else{
					s->set_state(CLOSING);
					return;
				}
			}
			if (s->bound && (s->state == TIME_WAIT || s->state == CLOSING)
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				uint16_t flags = 0x0005;
				flags<<=12;
				flags|=ACK_FLAG;

				Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
				fill_packet(response, s->local_ip, dest_port, s->remote_ip, source_port, s->seq_num, s->ack_num, flags, BUFFER_SIZE);
				this->sendPacket("IPv4", response);
				this->freePacket(packet);
				return;
			}
		}

		// Look in waiting connections (not yet accepted, but client is closing)
		for (auto it = sockets.begin(); it != sockets.end(); it++){
			Socket *s = &(it->second);
			if (s->bound && s->state == PASSIVE
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip))
			{
				struct listening *listen = s->listen;
				struct hp_list *wl;
				for (wl = listen->waiting_list; wl != NULL; wl = wl->next){
					if (wl->ip == source_ip && wl->port == source_port){
						uint32_t ack_num;
						packet->readData(14 + 20 + 4, &ack_num, 4);
						ack_num = ntohl(ack_num);
						ack_num++;
						wl->ack_num = ack_num;

						uint16_t flags = 0x0005;
						flags<<=12;
						flags|=ACK_FLAG;

						Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
						fill_packet(response, wl->local_ip, dest_port, wl->ip, source_port, wl->seq_num, wl->ack_num, flags, BUFFER_SIZE);
						this->sendPacket("IPv4", response);
						this->freePacket(packet);

						wl->state = CLOSE_WAIT;
						return;
					}
				}
				this->freePacket(packet);
				return;
			}
		}
		this->freePacket(packet);
		return;
	}

	if (offset_and_flags & ACK_FLAG){
		uint32_t received_ack;
		packet->readData(14 + 20 + 8, &received_ack, 4);
		received_ack = ntohl(received_ack);
		//std::cout << "received ACK packet " << received_ack << " with size " << tcp_size << "\n";
		for (auto it = sockets.begin(); it != sockets.end(); it++){
			Socket *s = &(it->second);
			if (s->bound && s->state == FIN_WAIT_1
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				//std::cout << "ACK fin wait 1 "<< received_ack << "\n" ;
				if (received_ack == s->last_ack_expected){
					//std::cout << "Going to FW2 state\n";
					cancelTimer(s->close_timer);
					s->set_state(FIN_WAIT_2);
					this->freePacket(packet);
					return;
				}
				else{
					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;

					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, dest_ip, s->local_port, source_ip, s->remote_port, s->seq_num - 1, s->ack_num, flags, BUFFER_SIZE - recv_buf_size(s));
					this->sendPacket("IPv4", response);
					this->freePacket(packet);
					return;

				}
			}
			else if (s->bound && s->state == CLOSING
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				// Client got ACK after FIN; send nothing, just change state and add timer
				//std::cout << "ACK closing "<< received_ack << "\n" ;
				if (received_ack == s->last_ack_expected){
					cancelTimer(s->close_timer);
					s->set_state(TIME_WAIT);
					char *pload = (char *) malloc(1 + sizeof(pid_fd));
					memset(pload, 1, 1);
					memcpy(pload + 1, &(it->first), sizeof(pid_fd));
					Time time = TimeUtil::makeTime(2, TimeUtil::stringToTimeUnit("MINUTE"));
					//Time time = 2L * 60L*1000L*1000L*1000L;
					addTimer((void *) pload, time);

					this->freePacket(packet);
					return;
				}
				else{
					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;

					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, dest_ip, s->local_port, source_ip, s->remote_port, s->seq_num - 1, s->ack_num, flags, BUFFER_SIZE - recv_buf_size(s));
					this->sendPacket("IPv4", response);
					this->freePacket(packet);
					return;
				}
			}
			else if (s->bound && s->state == LAST_ACK
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				//std::cout << "ACK last ack "<< received_ack << "\n" ;
				if (s->last_ack_expected == received_ack){
					cancelTimer(s->close_timer);
					pid_fd key = it->first;
					sockets.erase(key);
					removeFileDescriptor(key.first, key.second);
					this->freePacket(packet);
					return;
				}
				else{
					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;

					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, dest_ip, s->local_port, source_ip, s->remote_port, s->seq_num - 1, s->ack_num, flags, BUFFER_SIZE - recv_buf_size(s));
					this->sendPacket("IPv4", response);
					this->freePacket(packet);
					return;
				}
			}
			else if (s->bound && (s->state == ESTAB || s->state == CLOSE_WAIT)
							  && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip)
						 	  && s->remote_ip == source_ip && s->remote_port == source_port)
			{
				if (tcp_size == 20){
					// ACK for sent data
					uint32_t received_ack;
					packet->readData(14 + 20 + 8, &received_ack, 4);
					received_ack = ntohl(received_ack);
					//std::cout << "last ack and received ack " << s->last_ack << " " << received_ack << "\n";
					if (s->last_ack == received_ack)
					{
						s->duplicate_count++;
						this->freePacket(packet);
						
						if (s->duplicate_count >= 3 && s->cong_state != FAST_RECOVERY){
							//std::cout << "duplicate_count is 3\n";
							if (s->timer_set){
								cancelTimer(s->timer);
								s->timer_set = false;
							}
							s->ssthresh = s->cwnd/2;
							s->cwnd = s->ssthresh + 3*s->MSS;
							s->cong_state = FAST_RECOVERY;
							unsend(s);
							sendAll(s, true);
							return;
						}
						else if (s->cong_state == FAST_RECOVERY){
							s->cwnd = s->cwnd + s->MSS;
						}
						
						return;
					}
					else {
						s->duplicate_count = 0;
						update_cwnd(s, (received_ack - s->last_ack)/s->MSS);
						//s->cwnd = s->cwnd + (received_ack - s->last_ack)/s->MSS;
						//s->fast_retransmitting = false;
						struct data_list *temp = s->send_q;
						struct data_list *temp2;
						while (temp != NULL){
							//std::cout << "checking " << temp->seq_num << " with size " << temp->size << "\n";
							if (temp->seq_num + temp->size <= received_ack){
								free(temp->payload);
								if (temp->next != NULL)
									temp->next->prev = temp->prev;
								if (temp->prev != NULL)
									temp->prev->next = temp->next;
								//std::cout << "time and current time is " << temp->time << " " << this->getHost()->getSystem()->getCurrentTime() << "\n";
								uint64_t sample_rtt = this->getHost()->getSystem()->getCurrentTime() - temp->time;
								//std::cout << "sample_rtt is " << sample_rtt << "\n";
								//std::cout << "rttvar, srtt " << s->RTTVAR << " " << s->SRTT << "\n";
								s->RTTVAR = (uint64_t) (((double) 1 - beta)*s->RTTVAR + beta*(std::max(s->SRTT, sample_rtt) - std::min(s->SRTT, sample_rtt)));
								s->SRTT = (uint64_t) (((double) 1 - alpha)*s->SRTT + alpha*sample_rtt);
								//std::cout << "rttvar, srtt " << s->RTTVAR << " " << s->SRTT << "\n";
								s->RTO = s->SRTT+K*s->RTTVAR;
								//td::cout << "RTO is " << s->RTO << "\n";
								temp2 = temp;
								if (s->send_q == temp)
									s->send_q = s->send_q->next;
								temp = temp->next;
								free(temp2);
							}
							else
								temp = temp->next;
						}
						s->last_ack = received_ack;
						
						if (s->timer_set)
						{
							cancelTimer(s->timer);
							s->timer_set = false;
						}
						
					}
					uint16_t peer_window;
					packet->readData(14 + 20 + 14, &peer_window, 2);
					peer_window = ntohs(peer_window);
					s->peer_window_size = peer_window;

					uint16_t free = empty_space(s);
					if (s->writing && free >= s->count){
						uint16_t remaining = s->count;
						uint16_t start = 0;
						uint16_t size;
						char *b = (char *) s->buf;
						while (remaining > 0){
							size = std::min(MAX_PACKET_SIZE, remaining);
							struct data_list *node = (struct data_list *) malloc(sizeof(struct data_list));
							if (node == NULL){
								//std::cout << "write: error1\n";
								returnSystemCall(s->syscallUUID, -1);
								return;
							}
							node->size = size;
							node->seq_num = s->seq_num;
							//std::cout << "packet_arrived : " << start << " " << size << " " << remaining << " " << node->seq_num << " d\n";
							node->sent = false;
							s->seq_num+=size;
							node->payload = (char *) malloc(size);
							if (node->payload == NULL){
								//std::cout << "write: error2\n";
								returnSystemCall(s->syscallUUID, -1);
								return;
							}
							memcpy(node->payload, b + start, size);

							node->next = NULL;
							node->prev = NULL;

							node->next = s->send_q;
							if (s->send_q != NULL)
								s->send_q->prev = node;
							node->prev = NULL;
							s->send_q = node;

							start+=size;
							remaining-=size;
						}
						s->writing = false;
						returnSystemCall(s->syscallUUID, s->count);
					}
					sendAll(s, false);
					this->freePacket(packet);

					if (s->closing && empty_space(s) == BUFFER_SIZE){
						uint16_t offset_and_flags = 0x5;
						offset_and_flags<<=12;
						offset_and_flags|=FIN_FLAG;

						Packet *p = this->allocatePacket(14 + 12 + 8 + 20);
						fill_packet(p, s->local_ip, s->local_port, s->remote_ip, s->remote_port, s->seq_num, 0, offset_and_flags, BUFFER_SIZE - recv_buf_size(s));
						s->increment_seq_num();
						this->sendPacket("IPv4", p);

						s->set_state(FIN_WAIT_1);
						s->last_ack_expected = s->seq_num;
					}
					return;
				}

				//std::cout << "Some data sent\n";
				// Actual data sent
				uint32_t received_ack;
				packet->readData(14 + 20 + 8, &received_ack, 4);
				received_ack = ntohl(received_ack);

				uint32_t received_seq_num;
				packet->readData(14 + 20 + 4, &received_seq_num, 4);
				received_seq_num = ntohl(received_seq_num);
				//std::cout << "received ack and seq_num " << received_ack << " " << received_seq_num << "\n";


				if (s->ack_num != received_seq_num){
					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;

					Packet *response = this->allocatePacket(54);
					fill_packet(response, dest_ip, dest_port, source_ip, source_port, s->seq_num, s->ack_num, flags, BUFFER_SIZE - recv_buf_size(s));
					this->sendPacket("IPv4", response);
					this->freePacket(packet);
					return;
				}

				// expected packet
				struct data_list *node = (struct data_list *) malloc(sizeof(struct data_list));
				node->size = tcp_size - 20;
				node->already_read = 0;
				node->seq_num = received_seq_num;
				s->ack_num+=(node->size);
				node->payload = (char *) malloc(node->size);
				if (node->payload == NULL){
					//std::cout << "read error1\n";
					this->freePacket(packet);
					return;
				}
				packet->readData(14 + 20 + 20, node->payload, node->size);
				node->next = NULL;
				node->prev = NULL;

				node->next = s->recv_q;
				if (s->recv_q != NULL)
					s->recv_q->prev = node;
				node->prev = NULL;
				s->recv_q = node;


				uint16_t flags = 0x0005;
				flags<<=12;
				flags|=ACK_FLAG;

				Packet *response = this->allocatePacket(54);
				fill_packet(response, dest_ip, dest_port, source_ip, source_port, s->seq_num, s->ack_num, flags, BUFFER_SIZE - recv_buf_size(s));
				this->sendPacket("IPv4", response);
				this->freePacket(packet);

				//std::cout << "ACK for data sent\n";
				if (s->reading && 0 < recv_buf_size(s)){
					struct data_list *temp;
					for (temp = s->recv_q; temp != NULL && temp->next != NULL; temp = temp->next){
						//std::cout << "seq: " << temp->seq_num << "\n";
						continue;
					}
					//std::cout << "seqlast: " << temp->seq_num << "\n";
					uint16_t size;
					uint16_t to_read;
					uint16_t ans = 0;
					uint16_t remaining = s->count;
					while(temp != NULL){
						size = temp->size - temp->already_read;
						to_read = std::min(size, remaining);
						//std::cout << "from packet_arrived " << temp->size << " " << temp->already_read << " " << remaining << " " << to_read << "\n";
						memcpy(s->buf + (s->count - remaining), temp->payload + temp->already_read, to_read);
						temp->already_read+=to_read;
						ans+=to_read;
						remaining-=to_read;
						//std::cout << "from packet arrived " << ans << "\n";
						if (temp->already_read == temp->size){
							//std::cout << "deleting " << temp->seq_num << "\n";
							free(temp->payload);
							if (temp->next != NULL)
								temp->next->prev = temp->prev;
							if (temp->prev != NULL)
								temp->prev->next = temp->next;
							struct data_list *temp2 = temp;
							if (s->recv_q == temp)
								s->recv_q = s->recv_q->next;
							temp = temp->prev;
							free(temp2);
						}
						else
							break;
						if (remaining == 0)
							break;
					}
					s->reading = false;
					//std::cout << "returning " << ans << " ahskdhqkfb\n";
					returnSystemCall(s->syscallUUID, ans);
					//return;
				}

				if (s->state == CLOSE_WAIT && s->last_seq_num_expected == received_seq_num + tcp_size - 20){
					uint16_t flags = 0x0005;
					flags<<=12;
					flags|=ACK_FLAG;
					
					Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
					fill_packet(response, s->local_ip, dest_port, s->remote_ip, source_port, s->seq_num, s->last_seq_num_expected + 1, flags, BUFFER_SIZE - recv_buf_size(s));
					this->sendPacket("IPv4", response);
					return;
				}
				return;
			}
		}
		for (auto it = sockets.begin(); it != sockets.end(); it++){
			Socket *s = &(it->second);
			if (s->bound && s->state == PASSIVE
						 && s->local_port == dest_port && (s->local_ip == INADDR_ANY || s->local_ip == dest_ip))
			{
				// third step in handshaking
				struct hp_list *prev = NULL;
				for (struct hp_list *entry = s->listen->pending_list; entry != NULL; entry = entry->next){
					if (entry->ip == source_ip && entry->port == source_port){
						cancelTimer(entry->timer);
						(s->listen->pending_count)--;
						if (prev == NULL)
							s->listen->pending_list = entry->next;
						else
							prev->next = entry->next;

						if (s->listen->syscallUUID){
							// blocked accept
							int fd = createFileDescriptor(s->listen->pid);
							if (fd < 0){
								returnSystemCall(s->listen->syscallUUID, -1);
								this->freePacket(packet);
								return;
							}
							pid_fd new_key;
							new_key.first = s->listen->pid;
							new_key.second = fd;

							Socket new_s;
							new_s.set_bound(true);
							new_s.set_local_hp(entry->local_ip, s->local_port);
							new_s.set_has_connection(true);
							new_s.set_remote_hp(source_ip, source_port);
							new_s.set_state(ESTAB);
							new_s.set_seq_num(entry->seq_num);
							new_s.set_ack_num(entry->ack_num);
							new_s.set_peer_window_size(entry->window_size);
							new_s.last_ack = entry->seq_num;

							sockets[new_key] = new_s;

							struct sockaddr_in *addr_in = (struct sockaddr_in *) (s->listen->addr);
							addr_in->sin_family = AF_INET;
							addr_in->sin_port = htons(new_s.remote_port);
							addr_in->sin_addr.s_addr = htonl(new_s.remote_ip);
							*(s->listen->len) = sizeof(struct sockaddr_in);

							free(entry);
							this->freePacket(packet);
							returnSystemCall(s->listen->syscallUUID, fd);
							return;

						}
						else{
							(s->listen->waiting_count)++;
							struct hp_list *node = (struct hp_list *) calloc(1, sizeof(struct hp_list));
							if (node == NULL){
								//std::cout << "handshaking 3rd: waiting_list calloc error\n";
								this->freePacket(packet);
								return;
							}
							node->local_ip = entry->local_ip;
							node->ip = source_ip;
							node->port = source_port;
							node->seq_num = entry->seq_num;
							node->ack_num = entry->ack_num;
							node->window_size = entry->window_size;
							node->state = ESTAB;
							node->next = s->listen->waiting_list;
							s->listen->waiting_list = node;

							free(entry);
							this->freePacket(packet);
							return;
						}
					}
					prev = entry;
				}
				this->freePacket(packet);
				return;
			}
		}
		this->freePacket(packet);
		return;
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	uint8_t type = *((uint8_t *) payload);
	//std::cout << "Timer callback with type " << (int) type << "\n";
	if (type == 1){
		pid_fd key = *((pid_fd *) (((char *) payload) + 1));
		auto it = sockets.find(key);
		if (it == sockets.end()){
			std::cout << "Something very strange\n";
			free(payload);
			return;
		}
		sockets.erase(key);
		removeFileDescriptor(key.first, key.second);
	}
	else if (type == 2){
		Socket *s = *((Socket **) (((char *) payload) + 1));
		//std::cout << "sanity check " << s->local_ip << " " << s->local_port << "\n";
		s->timer_set = false;
		s->cong_state = SLOW_START;
		s->ssthresh = s->cwnd/2;
		s->cwnd = s->MSS;
		s->duplicate_count = 0;
		unsend(s);
		sendAll(s, true);
	}
	else if (type == 3){
		// connect
		char *b = (char *) payload;
		pid_fd key = *((pid_fd *) (b + 1));
		auto it = sockets.find(key);
		Socket *s = &(it->second);

		uint16_t offset_and_flags = 0x5;
		offset_and_flags<<=12;
		offset_and_flags|=SYN_FLAG;

		Packet *packet = this->allocatePacket(14 + 12 + 8 + 20);
		fill_packet(packet, s->local_ip, s->local_port, s->remote_ip, s->remote_port, s->seq_num - 1, 0, offset_and_flags, BUFFER_SIZE);
		this->sendPacket("IPv4", packet);

		s->timer = addTimer(payload, TIMEOUT);
		return;
	}
	else if (type == 4){
		// send SYNACK
		char *b = (char *) payload;
		struct hp_list *node = *((struct hp_list **) (b+1));

		uint16_t flags = 0x0005;
		flags<<=12;
		flags|=ACK_FLAG;
		flags|=SYN_FLAG;

		Packet *response = this->allocatePacket(14 + 12 + 8 + 20);
		fill_packet(response, node->local_ip, node->local_port, node->ip, node->port, node->seq_num - 1, node->ack_num, flags, BUFFER_SIZE);
		this->sendPacket("IPv4", response);

		node->timer = addTimer((void *) payload, TIMEOUT);

		return;
	}
	if (type == 5){
		char *b = (char *) payload;
		pid_fd key = *((pid_fd *) (b + 1));
		auto it = sockets.find(key);
		Socket *s = &(it->second);

		uint16_t offset_and_flags = 0x5;
		offset_and_flags<<=12;
		offset_and_flags|=FIN_FLAG;

		Packet *packet = this->allocatePacket(14 + 12 + 8 + 20);
		fill_packet(packet, s->local_ip, s->local_port, s->remote_ip, s->remote_port, s->seq_num - 1, 0, offset_and_flags, BUFFER_SIZE);
		this->sendPacket("IPv4", packet);

		s->close_timer = addTimer(payload, TIMEOUT);
		return;
	}
	free(payload);
}

void TCPAssignment::fill_packet(Packet *packet, uint32_t local_ip, uint16_t local_port,
								uint32_t remote_ip, uint16_t remote_port,
								uint32_t seq_num, uint32_t ack_num, uint16_t flags, uint16_t window)
{
	uint8_t header[20];
	memset(header, 0, 20);

	uint16_t local_port_net = htons(local_port);
	memcpy(header, &local_port_net, 2);

	uint16_t remote_port_net = htons(remote_port);
	memcpy(header + 2, &remote_port_net, 2);

	uint32_t seq_num_net = htonl(seq_num);
	memcpy(header + 4, &seq_num_net, 4);

	uint32_t ack_num_net = htonl(ack_num);
	memcpy(header + 8, &ack_num_net, 4);
	
	uint16_t flags_net = htons(flags);
	memcpy(header + 12, &flags_net, 2);

	uint16_t window_net = htons(window);
	memcpy(header + 14, &window_net, 2);

	uint16_t checksum = htons(~NetworkUtil::tcp_sum(htonl(local_ip), 
											 		htonl(remote_ip), header, 20));
	memcpy(header + 16, &checksum, 2);

	uint32_t local_ip_net = htonl(local_ip);
	uint32_t remote_ip_net = htonl(remote_ip);
	packet->writeData(14 + 12, &local_ip_net, 4);
	packet->writeData(14 + 16, &remote_ip_net, 4);
	packet->writeData(14 + 20, header, 20);
}


}
