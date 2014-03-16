module aws.signature.CSignature;

import aws.signature.ISignature;
import aws.request.CRequest;
import aws.credentials.CCredentials;
import aws.client.CAwsClient;

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

