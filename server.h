#ifndef SERVER_H
#define SERVER_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <thread>

#include "connection.h"

namespace ba = boost::asio;

class Server
{

public:
	explicit Server(ba::io_context& io_s, const std::string& ip, std::size_t port); 
	~Server();

	static void RunServer(const std::string& ip);

private:
	void listen();
	void launch_threadpool(ba::io_context& io_s);
	void set_thread_affinity(std::thread& th, std::size_t i);
	void setup_ssl();

private:	
	ba::ip::tcp::acceptor    acceptor_;
	std::size_t 		     threadcount_;
	std::vector<std::thread> threadpool_;
	ba::ssl::context 		 ssl_context_;
	
	std::string 			 rsa_priv_key_;
	std::string 			 rsa_pub_key_;
};

#endif
