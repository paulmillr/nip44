plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
}

kotlin {
    androidTarget {
        compilations.all {
            kotlinOptions {
                jvmTarget = "1.8"
            }
        }
    }
    jvm()

    sourceSets {
        commonMain.dependencies {
            implementation(kotlin("stdlib-common"))
            implementation(libs.secp256k1.kmp)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.jackson.module.kotlin)
        }

        androidMain.dependencies {
            // Bitcoin secp256k1 bindings to Android
            implementation(libs.secp256k1.kmp.jni.android)

            // TODO: Move this to the version catalog when classifiers become available.
            // LibSodium for ChaCha encryption
            implementation("com.goterl:lazysodium-android:5.1.0@aar")
            implementation("net.java.dev.jna:jna:5.14.0@aar")
        }
        val androidInstrumentedTest by getting {
            dependsOn(commonTest.get())

            dependencies {
                implementation(libs.jackson.module.kotlin)
                implementation(libs.androidx.junit)
                implementation(libs.androidx.junit.ktx)
                implementation(libs.androidx.espresso.core)
            }
        }

        jvmMain.dependencies {
            // Bitcoin secp256k1 bindings to Android
            implementation(libs.secp256k1.kmp.jni.jvm)

            // LibSodium for ChaCha encryption
            implementation(libs.lazysodium.java)
            implementation(libs.jna)
        }
        jvmTest.dependencies {

        }
    }
}

android {
    namespace = "not.important.crypto"
    compileSdk = 34
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
}
dependencies {
    androidTestImplementation(project(":nip44-shared"))
}
