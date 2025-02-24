import { ConfigFileAuthenticationDetailsProvider } from "oci-common";

export class OCISessionConfig {
  ociConfigFileLocation: string;
  profile?: string;
  ksmEndpoint: string;

  constructor(
    ociConfigFileLocation: string,
    profile: string | null,
    kmsEndpoint: string
  ) {
    this.ociConfigFileLocation = ociConfigFileLocation;
    this.profile = profile || "DEFAULT";
    this.ksmEndpoint = kmsEndpoint;
  }

  public getProvider(): ConfigFileAuthenticationDetailsProvider { 
    return new ConfigFileAuthenticationDetailsProvider(this.ociConfigFileLocation, this.profile);
  }

  public getKmsEndpoint(): string {
    return this.ksmEndpoint;
  }
}
