
export class AzureSessionConfig {
    tenant_id: string;
    client_id: string;
    client_secret: string;

    constructor(tenant_id: string, client_id: string, client_secret: string) {
        this.tenant_id = tenant_id;
        this.client_id = client_id;
        this.client_secret = client_secret;
    }
}
