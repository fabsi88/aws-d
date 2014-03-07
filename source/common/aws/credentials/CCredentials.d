module source.common.aws.credentials.CCredentials;

import source.common.aws.credentials.ICredentials;

///
final class CCredentials : ICredentials
{
private:
	string m_key;
	string m_secret;
	string m_token;
	string m_tokenTTD;

public:
	this(string _key, string _secret, string _token=null, string _tokenTTD=null)
	{
		m_key = _key;
		m_secret = _secret;
		m_token = _token;
	}
}