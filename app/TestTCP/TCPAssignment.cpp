/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

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
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, const int family, const int protocol)
{
	int fd = createFileDescriptor(pid);
	// std::cout << "open fd: " << fd << "\n";
	if (fd < 0){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	pid_fd key;
	key.first = pid;
	key.second = fd;

	Socket s;
	sockets[key] = s;
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	uint32_t ip = ntohl(addr_in->sin_addr.s_addr);
	uint16_t port = ntohs(addr_in->sin_port);

	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		// such fd is not opened
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
		if (p->second.bound && p->second.local_port == port &&
			(p->second.local_ip == ip || p->second.local_ip == INADDR_ANY || ip == INADDR_ANY)){
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}
	s->bound = true;
	s->local_ip = ip;
	s->local_port = port;
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t *len)
{
	pid_fd key;
	key.first = pid;
	key.second = fd;

	auto it = sockets.find(key);
	if (it == sockets.end()){
		// such fd is not opened
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

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, const int fd)
{
	pid_fd key;
	key.first = pid;
	key.second = fd;
	auto it = sockets.find(key);
	if (it == sockets.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}
	sockets.erase(key);
	removeFileDescriptor(pid, fd);
	returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
