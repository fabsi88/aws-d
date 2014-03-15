module aws.signature.ISignature;

import aws.request.CRequest;
import aws.credentials.CCredentials;

///
interface ISignature
{
	void signRequest(CRequest, CCredentials);
}