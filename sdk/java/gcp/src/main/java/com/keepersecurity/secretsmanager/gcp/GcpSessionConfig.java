package com.keepersecurity.secretsmanager.gcp;

public class GcpSessionConfig {

	private String location;
	private String keyRing;
	private String keyName;
	private String projectId;
	
	public GcpSessionConfig(String projectId, String location, String keyRing, String keyName) {
		super();
		this.location = location;
		this.keyRing = keyRing;
		this.keyName = keyName;
		this.projectId = projectId;
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
	public String getKeyName() {
		return keyName;
	}
	public void setKeyName(String keyName) {
		this.keyName = keyName;
	}

}
