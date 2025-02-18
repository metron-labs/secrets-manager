import org.gradle.kotlin.dsl.`maven-publish`
import org.gradle.kotlin.dsl.signing

group = "com.keepersecurity.secrets-manager.azure"
version = "1.0.0"

plugins {
    id ("java");
    kotlin("jvm") version "2.0.20"
    kotlin("plugin.serialization") version "2.0.20"
    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))  // Ensure it uses Java 11
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.keepersecurity.secrets-manager:core:17.0.0")
    implementation("com.azure:azure-identity:1.15.0")
    implementation("com.azure:azure-security-keyvault-keys:4.9.2")
    implementation("com.google.code.gson:gson:2.12.1")
    
    
    testImplementation("org.bouncycastle:bc-fips:2.0.0")
}


tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
