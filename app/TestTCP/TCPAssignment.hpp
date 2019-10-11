/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

typedef std::pair<int, int> pid_fd;

struct Socket{
	bool bound;
	uint32_t local_ip;			// in host order
	uint16_t local_port;		// in host order
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::map<pid_fd, Socket> sockets;

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, const int family, const int type) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t len) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t *len) final;
	virtual void syscall_close(UUID syscallUUID, int pid, const int fd) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
