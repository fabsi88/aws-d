module aws.ec2.CEc2Client;

import aws.ec2.IEc2Client;
import aws.client.CAwsClient;
import aws.credentials.CCredentials;
import aws.signature.CSignature;

///
class CEc2Client : CAwsClient , IEc2Client
{
private:


public:

	///
	this()
	{
		// Set default region
		setRegion(AwsRegionName.us_east_1);


	


	}

	///
	void startInstances(string[] _instanceIds)
	{



	}

	///
	void stopInstances(string[] _instanceIds)
	{
		
		
	}

}

