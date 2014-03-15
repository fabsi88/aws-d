module aws.signature.CSignature;

import aws.signature.ISignature;
import aws.request.CRequest;
import aws.credentials.CCredentials;

///
final class CSignature : ISignature
{
private:
	string m_sigVersion;
	string m_algorithm;
	string m_signature;

public:
	@property 
	{ 
		///
		string sigVersion() const { return m_sigVersion; } 
		///
		void sigVersion(string _sigVersion) { m_sigVersion = _sigVersion;}
		///
		string alogrithm() const { return m_algorithm; }
		///
		void algorithm(string _algorithm) { m_algorithm = _algorithm;}
		///
		string signature() const { return m_signature; }
		///
		void signature(string _signature) { m_signature = _signature;}
	}

	///
	void signRequest(CRequest _req, CCredentials _cred)
	{

	}
}

