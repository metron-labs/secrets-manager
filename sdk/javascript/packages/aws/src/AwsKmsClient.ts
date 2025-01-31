import { KMSClient } from "@aws-sdk/client-kms";
import { AWSSessionConfig } from "./AwsSessionConfig";

export class AwsKmsClient  {
    constructor(awsSessionConfig: AWSSessionConfig){ 
        return new KMSClient({
            region: awsSessionConfig.regionName,
            credentials: {
                accessKeyId: awsSessionConfig.awsAccessKeyId,
                secretAccessKey: awsSessionConfig.awsSecretAccessKey
            }
        })
    
    }
}