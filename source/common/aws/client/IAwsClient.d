module aws.client.iawsclient;

import aws.credentials.ccredentials;
import aws.signature.csignature;

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