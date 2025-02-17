plugins {
    id ("java");
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
}


tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
