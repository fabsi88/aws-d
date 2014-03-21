module aws.signature.csignature;

import aws.signature.isignature;
import aws.request.crequest;
import aws.credentials.ccredentials;
import aws.client.cawsclient;

///
final class CSignature : ISignature
{
private:
	SignatureVersion m_sigVersion;
	SignatureAlgorithm m_algorithm;
	string m_signature;

public:
	@property 
	{ 
		///
		SignatureVersion sigVersion() const { return m_sigVersion; } 
		///
		void sigVersion(SignatureVersion _sigVersion) { m_sigVersion = _sigVersion;}
		///
		SignatureAlgorithm alogrithm() const { return m_algorithm; }
		///
		void algorithm(SignatureAlgorithm _algorithm) { m_algorithm = _algorithm;}
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

