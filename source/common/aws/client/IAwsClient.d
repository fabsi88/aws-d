module source.common.aws.client.IAwsClient;

import source.common.aws.credentials.CCredentials;
import source.common.aws.signature.CSignature;

///
interface IAwsClient
{
	CCredentials 	getCredentials();
	CSignature 		getSignature();
	string[]		getRegions();
	string			getRegion();
	void			setRegion(string);
	string			getApiVersion();
}