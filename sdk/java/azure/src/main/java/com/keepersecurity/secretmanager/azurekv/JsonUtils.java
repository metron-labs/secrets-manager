package com.keepersecurity.secretmanager.azurekv;

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
}
