module aws.request.CRequest;

import aws.request.IRequest;

///
final class CRequest : IRequest
{
private:
	string m_baseUrl;
	string m_method;
	string[] m_params;

public:
	///
	this()
	{
	}

	///
	void Send()
	{
	}

	///
	void GenerateRequest()
	{
	}
}