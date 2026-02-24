import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.multiplatform")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.vanniktech.maven.publish")
}

kotlin {
    androidTarget {
        publishLibraryVariants("release")
        compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8) }
    }

    jvm()

    val xcf = XCFramework()
    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { target ->
        target.binaries.framework {
            baseName = "walletabi"
            xcf.add(this)
        }

        target.compilations["main"].cinterops {
            create("walletabiCInterop") {
                defFile(project.file("src/nativeInterop/cinterop/walletabi.def"))
                includeDirs(project.file("src/nativeInterop/cinterop/headers/walletabi"))
            }
        }
    }

    compilerOptions.freeCompilerArgs.add("-Xexpect-actual-classes")

    sourceSets {
        commonMain.dependencies {
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-core:1.9.0")
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
            implementation("org.jetbrains.kotlinx:atomicfu:0.30.0-beta")
            implementation("com.squareup.okio:okio:3.16.0")
        }

        androidMain.dependencies {
            implementation("net.java.dev.jna:jna:5.17.0") {
                artifact { type = "aar" }
            }
        }

        jvmMain.dependencies {
            implementation("net.java.dev.jna:jna:5.17.0")
        }
    }
}

android {
    namespace = "com.blockstream.wallet_abi_bindings"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

val libraryVersion: String by project

mavenPublishing {
    coordinates(groupId = "com.blockstream", artifactId = "wallet-abi", version = libraryVersion)

    pom {
        name = "Wallet ABI"
        description = "UniFFI bindings for wallet-abi"
        url = "https://github.com/BlockstreamResearch/simplicity-contracts"
        licenses {
            license {
                name = "MIT OR Apache-2.0"
                url = "https://github.com/BlockstreamResearch/simplicity-contracts"
            }
        }
    }
}
