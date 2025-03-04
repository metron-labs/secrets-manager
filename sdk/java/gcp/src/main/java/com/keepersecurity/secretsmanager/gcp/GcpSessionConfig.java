package com.keepersecurity.secretsmanager.gcp;

public class GcpSessionConfig {

	private String location;
	private String keyRing;
	private String keyId;
	private String projectId;
	private String keyVersion;
	
	public GcpSessionConfig(String projectId, String location, String keyRing, String keyId, String keyVersion) {
		super();
		this.location = location;
		this.keyRing = keyRing;
		this.keyId = keyId;
		this.projectId = projectId;
		this.keyVersion = keyVersion;
	}
	
	public String getProjectId() {
		return projectId;
	}
	public void setProjectId(String projectId) {
		this.projectId = projectId;
	}
	public String getLocation() {
		return location;
	}
	public void setLocation(String location) {
		this.location = location;
	}
	public String getKeyRing() {
		return keyRing;
	}
	public void setKeyRing(String keyRing) {
		this.keyRing = keyRing;
	}
	public String getKeyId() {
		return keyId;
	}
	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}
	public String getKeyVersion() {
		return keyVersion;
	}

	public void setKeyVersion(String keyVersion) {
		this.keyVersion = keyVersion;
	}

}
