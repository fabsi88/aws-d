module source.common.aws.signature.ISignature;

import source.common.aws.request.CRequest;
import source.common.aws.credentials.CCredentials;

///
interface ISignature
{
	void signRequest(CRequest, CCredentials);
}