module aws.credentials.ccredentials;

import aws.credentials.icredentials;

///
final class CCredentials : ICredentials
{
private:
	string m_key;
	string m_secret;
	string m_token;
	string m_tokenTTD;

public:
	@property 
	{ 
		///
		string key() const { return m_key; } 
		///
		void key(string _key) { m_key = _key; }
		///
		string secret() const { return m_secret; }
		///
		void secret(string _secret) { m_secret = _secret;}
		///
		string token() const { return m_token; }
		///
		void token(string _token) { m_token = _token;}
		///
		string tokenTTD() const { return m_tokenTTD; }
		///
		void tokenTTD(string _tokenTTD) { m_tokenTTD = _tokenTTD;}

	}
}