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

	@property
	{
		///
		string baseUrl() const { return m_baseUrl; }
		///
		void baseUrl(string _baseUrl) { m_baseUrl = _baseUrl; }
		///
		string method() const { return m_method; }
		///
		void method(string _method) { m_method = _method; }
		///
		string[] params()  { return m_params; }
		///
		void params(string[] _params) { m_params = _params; }
	}

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