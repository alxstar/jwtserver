#include "server.h"

#include <boost/asio.hpp>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

int main(int argc, char* argv[])
{
	if(argc != 3){
		std::cerr << "error, usage: ./server <ip> <port>\n";
		return -1;
	}
	
	const std::string ip(argv[1]);
	int port = std::atoi(argv[2]);
	if(!port){
		std::cerr << "error, port is not a number\n";
		return -1;
	}

	try
	{
		boost::asio::io_context io_context; 
		Server server(io_context, ip, port);
	}
	catch(const std::exception& e)
	{
		std::cerr << "exception: " << e.what() << '\n';
	}
}


