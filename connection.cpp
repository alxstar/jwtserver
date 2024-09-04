#include "connection.h"
#include "jwt.h"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <memory>
#include <iostream>
#include <sstream>
#include <tuple>

namespace http = boost::beast::http;

Connection::Connection(ba::ip::tcp::socket socket, ba::ssl::context& context, const std::string& priv_key, const std::string& pub_key): 
	socket_(std::move(socket), context),
	jwt_(priv_key, pub_key)
{}
	
void
Connection::ReadQuery()
{
	req_ = {};
	auto shared_this = shared_from_this();
	http::async_read(socket_, buf_, req_,
	[shared_this, this](const beast::error_code& ec, std::size_t sz)
	{
		std::cout << "async_read lambda\n";
		if(!ec || ec == ba::error::eof) 
		ParseRequest();
		else std::cout << ec.message() << '\n';
	});
}

void 
Connection::handle_accept()
{
	std::cout << "handle_accept\n";
	auto shared_this = shared_from_this();
	socket_.async_handshake(ba::ssl::stream_base::server, [this, shared_this](const beast::error_code& ec)
	{
		std::cout << "async_handshake lambda\n";
		if(ec)
		{
			std::cout << "error: " << ec.message() << '\n';
			return;
		}
		
		std::cout << "HANDSHAKE OK\n";
		ReadQuery();
	});
}

std::string get_token(const std::string& header)
{
    std::stringstream parser(header);
    std::string auth_type;
    parser >> auth_type;
    if(auth_type != "Bearer") return {};

    std::string auth_token;
    parser >> auth_token;
    return auth_token;
}

std::string make_json_tokens(const std::string& token, const std::string& refresh_token)
{	
	using boost::property_tree::ptree;
	ptree out;
 	out.put("status", 			 "success");    
	out.put("data.token", 	     token);
	out.put("data.refreshToken", refresh_token);

	std::ostringstream oss;
    boost::property_tree::write_json(oss, out);
    return oss.str();
}

std::string make_json_error(const std::string& message)
{	
	using boost::property_tree::ptree;
	ptree out;
 	out.put("status",  "error");    
	out.put("message", message);

	std::ostringstream oss;
    boost::property_tree::write_json(oss, out);
    return oss.str();
}

std::string make_json_empty_fields(bool username_empty, bool password_empty)
{	
	using boost::property_tree::ptree;
	ptree out;
 	out.put("status", "fail");    
	out.put("data.username", "A username is required");
	out.put("data.password", "A password is required");

	std::ostringstream oss;
    boost::property_tree::write_json(oss, out);
    return oss.str();
}


std::pair<std::string, std::string> get_login_and_password(const std::string& json_string)
{	
	using boost::property_tree::ptree;
    std::string username; 
	std::string password;
	try
	{
		ptree pt;
		{
			std::istringstream iss(json_string);
			read_json(iss, pt);
		}	
		username = pt.get<std::string>("username");
		password = pt.get<std::string>("password");
		std::cout << username << ", " << password << '\n';
	}
	catch(...)
	{
		std::cout << "bad json\n";
	}	
	return {username, password};
}

bool validate_user(const std::string& user, const std::string& password)
{
	return true;
}

void Connection::ParseRequest()
{
	std::cout << "PARSE_REQUEST\n";
	if(req_.method() != http::verb::get && req_.method() != http::verb::post)
	{
		return;
	}
	
	if(req_.method() == http::verb::get)
	{
		HandleGet();
	}
	if(req_.method() == http::verb::post)
	{
		HandlePost();
	}
}

void Connection::HandleGet()
{
	auto it = req_.find("Authorization");
	if(it == req_.end())
	{
		HandleAuthorizationFailure();
		return;
	}

	std::string token = get_token(std::string(it->value()));
	bool verified = jwt_.VerifyToken(token);
	if(!verified)
	{
		HandleAuthorizationFailure();
		return;
	}
	
	std::string path(req_.target());	
	std::cout << "TARGET:" << path << '\n';
	HandleRequest(path);
}

void Connection::HandlePost()
{
	std::cout << req_.body() << '\n';
	std::string user;
	std::string password;
	std::tie(user, password) = get_login_and_password(std::string(req_.body()));
	//const auto&[user, password] = get_login_and_password(std::string(req_.body()));
	if(user.empty() || password.empty())
	{
		HandleEmptyFields();
		return;
	}
	
	bool user_validated = validate_user(user, password);
	if(!user_validated)
	{
		HandleValidationFailure();
	}
	else
	{
		HandleValidation();
	}
}

std::shared_ptr<http::response<http::string_body>> make_response(http::status status, int version, const std::string& body)
{
	auto response = std::make_shared<http::response<http::string_body>>(status, version);
	response->set(http::field::server, "JWTSERVER");
	response->set(http::field::connection, "close");
	//response->keep_alive(false);
	//response->set(http::field::content_type, "application/json; charset=utf-8");
	response->body() = body.c_str();
	response->content_length(response->body().size());
	response->prepare_payload();
	return response;
}


void Connection::HandleValidation()
{
	std::string token         = jwt_.CreateToken();
	std::string refresh_token = jwt_.CreateToken();
	std::string body          = make_json_tokens(token, refresh_token);
	
	auto response = make_response(http::status::ok, req_.version(), body);
	res_ = response;
	auto shared_this = shared_from_this();
	http::async_write(socket_, *res_, [this, shared_this](const beast::error_code& ec, std::size_t sz){OnWrite();});
}

void Connection::OnWrite()
{
	std::cout << "RESPONSE OK!\n";
}

void Connection::HandleValidationFailure()
{
	std::string body = make_json_error("Invalid username or password, check the entered data and try again");
	auto response = make_response(http::status::forbidden, req_.version(), body);
	res_ = response;
	auto shared_this = shared_from_this();
	http::async_write(socket_, *res_, [this, shared_this](const beast::error_code& ec, std::size_t sz){OnWrite();});
}

void Connection::HandleEmptyFields()
{
	std::string body = make_json_empty_fields(true, true);
	auto response = make_response(http::status::unprocessable_entity, req_.version(), body);
	res_ = response;
	auto shared_this = shared_from_this();
	http::async_write(socket_, *res_, [this, shared_this](const beast::error_code& ec, std::size_t sz){OnWrite();});
}

void Connection::HandleAuthorizationFailure()
{
	std::string body = make_json_error("Unauthorized");
	auto response = make_response(http::status::forbidden, req_.version(), body);
	res_ = response;
	auto shared_this = shared_from_this();
	http::async_write(socket_, *res_, [this, shared_this](const beast::error_code& ec, std::size_t sz){OnWrite();});
}

void Connection::HandleRequest(const std::string& path)
{
	if(path=="/api/v1/auth/refresh")
	{
		HandleValidation();
	}
	else if(path=="/api/v1/call_status")
	{
		HandleCallStatusRequest();
	}
}

void Connection::HandleCallStatusRequest()
{

}

void Connection::SendCallStatus(bool call_status)
{

}

