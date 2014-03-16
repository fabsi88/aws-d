module aws.client.CAwsClient;

import aws.client.IAwsClient;
import aws.credentials.CCredentials;
import aws.signature.CSignature;

///
abstract class CAwsClient : IAwsClient
{
protected:
	CCredentials m_credentials = new CCredentials();
	CSignature m_signature = new CSignature();
	string m_region;
	
public:

	///
	this()
	{

	}
	
	///
	CCredentials getCredentials() 
	{
		return m_credentials;
	}

	///
	void setCredentials(string _key, string _secret, string _token="", string _tokenTTD="")
	{
		m_credentials.key = _key;
		m_credentials.secret = _secret;
		m_credentials.token = _token;
		m_credentials.tokenTTD = _tokenTTD;
	}

	///
	CSignature getSignature()
	{
		return m_signature;
	}

	void setSignature(string _sigVersion, string _algorithm, string _signature = "")
	{
		m_signature.sigVersion = _sigVersion;
		m_signature.algorithm = _algorithm;
		m_signature.signature = _signature;
	}

	///
	string[] getRegions()
	{
		return [];
	}

	///
	string getRegion()
	{
		return "";
	}

	///
	void setRegion(string _region)
	{
		m_region = _region;
	}

	///
	string getApiVersion()
	{
		return "";
	}
}

///
struct AwsRegion
{
	bool http;
	bool https;
	string hostname;
}

enum AwsRegionName{
	us_east_1="us-east-1",
	us_west_1="us-west-1",
	us_west_2="us-west-2",
	eu_west_1="eu-west-1",
	ap_northeast_1="ap-northeast-1",
	ap_southeast_1="ap-southeast-1",
	ap_southeast_2="ap-southeast-2",
	sa_east_1="sa-east-1",
	cn_north_1="cn-north-1",
	us_gov_west_1="us-gov-west-1"};

enum AwsRegion[string] regions =
[	AwsRegionName.us_east_1: AwsRegion(true, true, "ec2.us-east-1.amazonaws.com"),
	AwsRegionName.us_west_1: AwsRegion(true, true, "ec2.us-west-1.amazonaws.com"),
	AwsRegionName.us_west_2: AwsRegion(true, true, "ec2.us-west-2.amazonaws.com"),
	AwsRegionName.eu_west_1: AwsRegion(true, true, "ec2.eu-west-1.amazonaws.com"),
	AwsRegionName.ap_northeast_1: AwsRegion(true, true, "ec2.ap-northeast-1.amazonaws.com"),
	AwsRegionName.ap_southeast_1: AwsRegion(true, true, "ec2.ap-southeast-1.amazonaws.com"),
	AwsRegionName.ap_southeast_2: AwsRegion(true, true, "ec2.ap-southeast-2.amazonaws.com"),
	AwsRegionName.sa_east_1: AwsRegion(true, true, "ec2.sa-east-1.amazonaws.com"),
	AwsRegionName.cn_north_1: AwsRegion(true, true, "ec2.cn-north-1.amazonaws.com.cn"),
	AwsRegionName.us_gov_west_1: AwsRegion(false, true, "ec2.us-gov-west-1.amazonaws.com")];

enum SignatureAlogrithm {
	HmacSHA1="HmacSHA1",
	HmacSHA256="HmacSHA256"};

enum SignatureVersion {
	v2=2,
	v4=4};