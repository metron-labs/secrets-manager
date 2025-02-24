import { KmsCryptoClient } from "oci-keymanagement/lib/client";
import { OCISessionConfig } from "./OciSessionConfig";

export class OciKmsClient {
  private ociKmsClient: KmsCryptoClient;

  constructor(sessionConfig: OCISessionConfig) {
    this.ociKmsClient = new KmsCryptoClient({ authenticationDetailsProvider: sessionConfig.getProvider() });
    this.ociKmsClient.endpoint = sessionConfig.getKmsEndpoint();
  }

  public getCryptoClient(): KmsCryptoClient {
    return this.ociKmsClient;
  }
}
