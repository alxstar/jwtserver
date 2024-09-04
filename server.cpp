#include "server.h"

#include <boost/asio.hpp>

#include <thread>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <pthread.h>


std::string read_key(const std::string& key_file)
{
	std::ifstream in(key_file);
	if(!in) throw std::logic_error("key file " + key_file + " open failure");
	
	std::string key;
	for(std::string line; std::getline(in, line);)
		key += line + '\n';
	if(key.empty()) throw std::logic_error("key file " + key_file + " is empty");
	
	return key;
}

Server::Server(
	boost::asio::io_context& io_s, 
	const std::string& ip, 
	std::size_t port) 
	: acceptor_(io_s, ba::ip::tcp::endpoint(
		ba::ip::address_v4::from_string(ip), port))
	, threadcount_(std::thread::hardware_concurrency())
	, threadpool_(threadcount_)
	, ssl_context_(ba::ssl::context::sslv23)
	, rsa_priv_key_(read_key("/etc/ssl/certs/jwt_server_certs/server.key"))
	, rsa_pub_key_(read_key("/etc/ssl/certs/jwt_server_certs/public.key"))
{
	setup_ssl();
	acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	listen();
	launch_threadpool(io_s);
}

Server::~Server(){ for(auto& th: threadpool_) if(th.joinable()) th.join(); }

void Server::setup_ssl()
{
	ssl_context_.set_options(
		ba::ssl::context::default_workarounds   | 
		ba::ssl::context::no_sslv2              | 
		ba::ssl::context::single_dh_use
		);

	ssl_context_.set_password_callback(
		[this](std::size_t max_length, ba::ssl::context::password_purpose purpose)
		-> std::string {return "test";}
	);  

	ssl_context_.use_certificate_chain_file("/etc/ssl/certs/jwt_server_certs/server.crt");
	ssl_context_.use_private_key_file("/etc/ssl/certs/jwt_server_certs/server.key", ba::ssl::context::pem);
	ssl_context_.use_tmp_dh_file("/etc/ssl/certs/jwt_server_certs/dhparams.pem");
}

void Server::listen()
{
	acceptor_.async_accept([this](const boost::system::error_code& ec, ba::ip::tcp::socket socket)
	{
		if (!ec)  
		{ 
			auto new_connection = std::make_shared<Connection>(std::move(socket), ssl_context_, rsa_priv_key_, rsa_pub_key_);
			new_connection->handle_accept();   
		}
		else      { }
		listen();
	});
}

void Server::launch_threadpool(boost::asio::io_context& io_s)
{
	for(std::size_t i = 0; i < threadcount_; ++i) 
	{
		threadpool_[i] = std::thread([&](){io_s.run();});
		set_thread_affinity(threadpool_[i], i);
	}
}

void Server::set_thread_affinity(std::thread& th, std::size_t i)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(i, &cpuset);
	pthread_setaffinity_np(th.native_handle(), sizeof(cpu_set_t), &cpuset);
}

void Server::RunServer(const std::string& ip)
{
	try
	{
		std::thread t([ip]
		{
			std::size_t port = 443;
			boost::asio::io_context io_s;
			Server server(io_s, ip, port);
			io_s.run();
		});
		t.detach();
	}
	catch(std::exception& e) { }
}


