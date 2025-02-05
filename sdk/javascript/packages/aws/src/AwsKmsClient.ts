import { KMSClient } from "@aws-sdk/client-kms";
import { AWSSessionConfig } from "./AwsSessionConfig";

export class AwsKmsClient {
  private kmsClient: KMSClient;
  constructor(awsSessionConfig: AWSSessionConfig) {
    this.kmsClient = new KMSClient({
      region: awsSessionConfig.regionName,
      credentials: {
        accessKeyId: awsSessionConfig.awsAccessKeyId,
        secretAccessKey: awsSessionConfig.awsSecretAccessKey,
      },
    });
  }

  public getCryptoClient() {
    return this.kmsClient;
  }
}
