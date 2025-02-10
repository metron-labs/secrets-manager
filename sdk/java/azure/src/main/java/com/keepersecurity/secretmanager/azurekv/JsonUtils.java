package com.keepersecurity.secretmanager.azurekv;

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

import java.io.FileReader;
import java.io.IOException;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

public class JsonUtils {

	public static boolean isValidJsonFile(String filePath) {
		try (FileReader reader = new FileReader(filePath)) {
			JsonElement jsonElement = JsonParser.parseReader(reader);
			return jsonElement != null;
		} catch (IOException | JsonSyntaxException e) {
		}
		return false;
	}

	public static boolean isValidJson(String jsonContent) {
		try {
			JsonElement jsonElement = JsonParser.parseString(jsonContent);
			return jsonElement != null;
		} catch (JsonSyntaxException e) {
		}
		return false;
	}
}
