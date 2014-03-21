module aws.ec2.cec2client;

import aws.ec2.iec2client;
import aws.client.cawsclient;
import aws.credentials.ccredentials;
import aws.signature.csignature;

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

