#ifndef JWT_H
#define JWT_H 

#include <jwt-cpp/jwt.h>

class Jwt
{
	using token_verifier_t = jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson>;
	
	std::string 	 	rsa_priv_key_;
	std::string 	 	rsa_pub_key_;
	token_verifier_t 	token_verifier_;

	token_verifier_t MakeVerifier()
	{
		return jwt::verify().allow_algorithm(jwt::algorithm::rs256(rsa_pub_key_, "", "", "")).with_issuer("auth0");	
	}

public:	
	Jwt(const std::string& priv_key, const std::string& pub_key): 
		rsa_priv_key_(priv_key),
		rsa_pub_key_(pub_key),
		token_verifier_(MakeVerifier())
	{
	}

	std::string CreateToken()
	{
		auto token = jwt::create()
			.set_issuer("auth0")
			.set_type("JWT")
			.set_id("rsa-create-example")
			.set_issued_at(std::chrono::system_clock::now())
			.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{60})
			.set_payload_claim("sample", jwt::claim(std::string{"test"}))
			.sign(jwt::algorithm::rs256("", rsa_priv_key_, "", ""));
		
		return token;
	}

	bool VerifyToken(const std::string& token)
	{
		bool verified = true;
		auto decoded = jwt::decode(token);
		try
		{
			token_verifier_.verify(decoded);
		}
		catch(...)
		{
			verified = false;
		}
		return verified;
	}
};

#endif
