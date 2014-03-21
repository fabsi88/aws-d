module aws.signature.isignature;

import aws.request.crequest;
import aws.credentials.ccredentials;

///
interface ISignature
{
	void signRequest(CRequest, CCredentials);
}