module aws.client.IAwsClient;

import aws.credentials.CCredentials;
import aws.signature.CSignature;

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