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
typedef std::pair<uint32_t, uint16_t> hp;		// host:port pair
typedef std::pair<int, int> pid_fd;

enum socket_state{

	// client side
	CLOSED,
	SYNSENT,
	ESTAB,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,

	// server side
	PASSIVE,
	SYNRCVD,
	CLOSE_WAIT,
	LAST_ACK
};

enum congestion_state{
	SLOW_START,
	CONGESTION_AVOIDANCE,
	FAST_RECOVERY
};

struct hp_list{
	uint32_t local_ip;
	uint16_t local_port;
	uint32_t ip;				// destination ip of a pending connection
	uint16_t port;				// destination port of a pending connection
	uint32_t seq_num;			// server's seq_num sent to client
	uint32_t ack_num;			// sent to client from server
	uint16_t window_size;		// client's window size
	socket_state state;			// State of pending/waiting connection
	UUID timer;
	hp_list *next;
};

struct listening
{
	int backlog;
	int pending_count;			// pending sockets in SYNRCVD state (to be created soon)
	hp_list *pending_list;
	int waiting_count;			// waiting sockets in ESTAB state (to be accepted soon)
	hp_list *waiting_list;
	UUID syscallUUID; 			// syscallUUID of blocked accept
	struct sockaddr* addr;		// addr is filled when blocked accept is freed
	socklen_t *len;				// len is used when blocked accept is freed
	int pid;					// pid when accept was blocked
};

// TODO: probablt will have to add already_written
struct data_list
{
	char *payload;
	uint16_t already_read;		// how many bytes are already read from this data packet
	bool sent;
	uint16_t size;
	uint32_t seq_num;
	struct data_list *next;
	struct data_list *prev;
	uint64_t time;
};

class Socket{
	public:
		bool bound;
		bool has_connection;
		uint32_t local_ip;				// in host order
		uint16_t local_port;			// in host order
		uint32_t remote_ip;				// in host order
		uint16_t remote_port;			// in host order
		socket_state state;
		congestion_state cong_state;
		uint32_t seq_num;				// from socket, incremented only when ACK is received
		uint32_t ack_num;				// from socket
		uint32_t last_ack;				// received by socket
		uint32_t last_ack_expected;		// ACK for fin (ACKs less than this are received normally)
		uint32_t last_seq_num_expected;	// seq_num sent with FIN packet; higher seq_nums are omitted
		struct data_list *send_q;
		struct data_list *recv_q;
		uint16_t peer_window_size;
		uint8_t duplicate_count;
		uint32_t cwnd;
		uint32_t ssthresh;
		uint32_t MSS;
		uint64_t RTT;
		uint64_t SRTT;
		uint64_t RTTVAR;
		uint64_t RTO;
		bool writing;					// true if blocked by write syscall
		bool reading;					// true if blocked by read syscall
		char *buf;						// buffer argument of blocked read/write syscall
		int count;						// size argument of blocked read/write syscall
		bool timer_set;
		UUID syscallUUID;
		UUID timer;
		UUID close_timer;
		bool closing;
		struct listening *listen;		// used only when socket state is passive
	public:
		Socket(){
			bound = false;
			has_connection = false;
			local_ip = 0;
			local_port = 0;
			remote_ip = 0;
			remote_port = 0;
			state = CLOSED;
			cong_state = SLOW_START;
			seq_num = 1234;
			send_q = NULL;
			recv_q = NULL;
			duplicate_count = 0;
			MSS = 512;
			cwnd = 512;
			ssthresh = 65536;
			RTT = 100000000;
			SRTT = RTT;
			RTTVAR = RTT/2;
			RTO = SRTT + 4*RTTVAR;
			writing = false;
			reading = false;
			timer_set = false;
			buf = NULL;
			closing = false;
			listen = NULL;
		}
		void set_bound(bool b){
			bound = b;
		}
		void set_has_connection(bool b){
			has_connection = b;
		}
		void set_local_hp(uint32_t ip, uint16_t port){
			local_ip = ip;
			local_port = port;
		}
		void set_remote_hp(uint32_t ip, uint16_t port){
			remote_ip = ip;
			remote_port = port;
		}
		void set_state(socket_state s){
			state = s;
		}
		void set_seq_num(uint32_t s){
			seq_num = s;
		}
		void increment_seq_num(){
			seq_num++;
		}
		void set_ack_num(uint32_t num){
			ack_num = num;
		}
		void set_syscallUUID(UUID syscall){
			syscallUUID = syscall;
		}
		void set_peer_window_size(uint16_t s){
			peer_window_size = s;
		}
};


class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::map<pid_fd, Socket> sockets;
	uint32_t K = 4;
	double alpha = 0.125;
	double beta = 0.25;
	
private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void syscall_socket(UUID syscallUUID, int pid, const int family, const int type) final;
	virtual void syscall_close(UUID syscallUUID, int pid, const int fd) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t len) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t *len) final;
	virtual void syscall_connect(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t len) final;
	virtual void syscall_listen(UUID syscallUUID, int pid, const int fd, int backlog) final;
	virtual void syscall_accept(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t *len) final;
	virtual void syscall_getpeername(UUID syscallUUID, int pid, const int fd, struct sockaddr *addr, socklen_t *len) final;
	virtual void syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int count) final;
	virtual void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int count) final;
	virtual uint16_t empty_space(Socket *s) final;
	virtual uint16_t recv_buf_size(Socket *s) final;
	virtual void sendAll(Socket *s, bool isretransmit) final;
	virtual void unsend(Socket *s) final;
	virtual void update_cwnd(Socket *s, int times) final;
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	virtual void fill_packet(Packet *packet, uint32_t local_ip, uint16_t local_port,
								uint32_t remote_ip, uint16_t remote_port,
								uint32_t seq_num, uint32_t ack_num, uint16_t flags, uint16_t window) final;
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
