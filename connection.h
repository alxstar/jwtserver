#ifndef CONNECTION_H
#define CONNECTION_H 

#include "jwt.h"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>

namespace ba = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using ssl_socket = beast::ssl_stream<beast::tcp_stream>;

class Connection : public std::enable_shared_from_this<Connection>
{

public:
	explicit Connection(ba::ip::tcp::socket socket, ba::ssl::context& context, const std::string& priv_key, const std::string& pub_key);	
	void ReadQuery();
	void handle_accept();

private:
	void ParseRequest();
	void HandleRequest(const std::string& path);
	void OnWrite();
	void HandleGet();
	void HandlePost();
	void HandleValidation();
	void HandleValidationFailure();
	void HandleEmptyFields();
	void HandleAuthorizationFailure();

	void HandleCallStatusRequest();
	void SendCallStatus(bool call_status);

private:
	http::request<http::string_body> req_;
	ssl_socket socket_;
	ba::streambuf buf_;
	std::shared_ptr<http::response<http::string_body>> res_;
	Jwt jwt_;
};

#endif
