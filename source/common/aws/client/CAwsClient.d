module source.common.aws.client.CAwsClient;

import source.common.aws.client.IAwsClient;
import source.common.aws.credentials.CCredentials;
import source.common.aws.signature.CSignature;

///
final class CAwsClient : IAwsClient
{
private:
	CCredentials m_credentials;
	CSignature m_signature;

public:
	///
	CCredentials getCredentials() 
	{
		return m_credentials;
	}

	///
	CSignature getSignature()
	{
		return m_signature;
	}

	///
	string[] getRegions()
	{
		return [];
	}

	///
	string getRegion()
	{
		return "";
	}

	///
	void setRegion(string)
	{
	}

	///
	string getApiVersion()
	{
		return "";
	}
}