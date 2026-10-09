plugins {
    id("com.android.application")
}

android {
    namespace = "it.brina.portdrift"
    compileSdk = 37

    defaultConfig {
        applicationId = "it.brina.portdrift"
        minSdk = 29
        targetSdk = 37
        versionCode = 5
        versionName = "0.5.0-beta.1"
        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
