package com.keepersecurity.secretsmanager.gcp;


import java.io.FileReader;
import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

public class JsonUtil {

	private static ObjectMapper objectMapper = new ObjectMapper();

	public static boolean isValidJsonFile(String filePath) {
		try (FileReader reader = new FileReader(filePath)) {
			JsonElement jsonElement = JsonParser.parseReader(reader);
			return jsonElement != null;
		} catch (IOException e) {
		} catch (JsonSyntaxException e) {
		}
		return false;
	}

	public static boolean isValidJson(String jsonContent) {
		try {
			JsonElement jsonElement = JsonParser.parseString(jsonContent);
			return jsonElement != null;
		} catch (JsonSyntaxException e) {
			System.out.println("Invalid JSON syntax: " + e.getMessage());
		}
		return false;
	}

	public static Map<String, Object> convertToMap(String content) throws JsonProcessingException {
		return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
		});
	}
	
	public static String convertToString(Map<String, Object> configMap) throws JsonProcessingException {
		return objectMapper.writeValueAsString(configMap);
	}
}
