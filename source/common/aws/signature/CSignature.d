module source.common.aws.signature.CSignature;

import source.common.aws.signature.ISignature;
import source.common.aws.request.CRequest;
import source.common.aws.credentials.CCredentials;

///
final class CSignature : ISignature
{
private:
	string m_version;
	string m_algorithm;
	string m_signature;

public:

	///
	void signRequest(CRequest _req, CCredentials _cred)
	{

	}

	///
	this(string _version, string _algorithm)
	{
		m_version = _version;
		m_algorithm = _algorithm;
	}
}

