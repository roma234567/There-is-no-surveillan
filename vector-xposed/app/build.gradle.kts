import java.net.URI
import java.util.zip.ZipFile

plugins {
    id("com.android.application")
}

/* Extract classes.jar from official Maven Central io.github.libxposed:api:102.0.0 AAR
 * so compileOnly works cleanly across AGP 8.x/9.x without bundling Xposed API into DEX! */
val libxposedJarDir = layout.buildDirectory.dir("libxposed-api-102")
val prepareLibxposedApi by tasks.registering {
    val outJar = libxposedJarDir.map { it.file("libxposed-api-102.jar") }
    outputs.file(outJar)
    doLast {
        val targetFile = outJar.get().asFile
        if (!targetFile.exists()) {
            targetFile.parentFile.mkdirs()
            val aarUrl = "https://repo1.maven.org/maven2/io/github/libxposed/api/102.0.0/api-102.0.0.aar"
            val tmpAar = File(targetFile.parentFile, "api-102.0.0.aar")
            URI(aarUrl).toURL().openStream().use { input ->
                tmpAar.outputStream().use { output -> input.copyTo(output) }
            }
            ZipFile(tmpAar).use { zip ->
                val entry = zip.getEntry("classes.jar")
                    ?: error("classes.jar missing inside io.github.libxposed:api:102.0.0.aar")
                zip.getInputStream(entry).use { zis ->
                    targetFile.outputStream().use { fos -> zis.copyTo(fos) }
                }
            }
            tmpAar.delete()
        }
    }
}

tasks.named("preBuild") {
    dependsOn(prepareLibxposedApi)
}

android {
    namespace = "org.privacysentinel.vector"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.privacysentinel.vector"
        minSdk = 31
        targetSdk = 35
        versionCode = 100
        versionName = "1.0.0-garnet-a17"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    compileOnly(files(libxposedJarDir.map { it.file("libxposed-api-102.jar") }))
    compileOnly("androidx.annotation:annotation:1.8.2")
}
