package com.keepersecurity.secretmanager.aws.kms;

/**
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com
**/

import software.amazon.awssdk.regions.Region;

public class AwsSessionConfig {

	private String awsAccessKeyId;
    private String awsSecretAccessKey;
    private Region regionName;
	
    public AwsSessionConfig(String awsAccessKeyId, String awsSecretAccessKey, Region regionName) {
        this.awsAccessKeyId = awsAccessKeyId;
        this.awsSecretAccessKey = awsSecretAccessKey;
        this.regionName = regionName;
        
    }

	public String getAwsAccessKeyId() {
		return awsAccessKeyId;
	}

	public void setAwsAccessKeyId(String awsAccessKeyId) {
		this.awsAccessKeyId = awsAccessKeyId;
	}

	public String getAwsSecretAccessKey() {
		return awsSecretAccessKey;
	}

	public void setAwsSecretAccessKey(String awsSecretAccessKey) {
		this.awsSecretAccessKey = awsSecretAccessKey;
	}

	public Region getRegionName() {
		return regionName;
	}

	public void setRegionName(Region regionName) {
		this.regionName = regionName;
	}

   
}
