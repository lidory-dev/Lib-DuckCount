import gobley.gradle.GobleyHost
import gobley.gradle.cargo.dsl.CargoBinaryCrateSource
import gobley.gradle.cargo.dsl.android
import gobley.gradle.uniffi.tasks.InstallUniffiBindgenTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import javax.inject.Inject

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)

    // Gobley (Rust interoperability)
    id("dev.gobley.cargo") version "0.3.7"
    id("dev.gobley.uniffi") version "0.3.7"
    kotlin("plugin.atomicfu") version libs.versions.kotlin
}

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }

    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "LibDuckCount"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            // put your Multiplatform dependencies here
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

android {
    namespace = "app.lidory.duckcount.lib"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    // Without it Gobley takes whichever NDK is the newest on the machine.
    ndkVersion = libs.versions.android.ndk.get()
    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }
}

// A release library has to come out the same wherever it is built: F-Droid publishes a
// release only if its own build matches the bytes, on a server whose paths are not ours.
//
// Rust writes the path of every crate from Cargo's registry into the library, for panic
// messages. Only the part inside the crate says anything, the rest being a home directory.
// `trim-paths` in Cargo.toml would do this but is not on stable Rust yet. The flag goes in
// the encoded form since a path can hold a space.
val cargoHome: String = providers.environmentVariable("CARGO_HOME").orNull
    ?: "${System.getProperty("user.home")}/.cargo"

// aws-lc-sys generates its bindings with libclang, which would otherwise be whichever the
// machine has: Xcode's here, Debian's on F-Droid's server.
val ndkLibclang: Provider<String> = providers.provider {
    android.ndkDirectory.resolve("toolchains/llvm/prebuilt").listFiles()!!.single().resolve("lib").path
}

cargo {
    builds.android {
        variants {
            buildTaskProvider.configure {
                additionalEnvironment.put("LIBCLANG_PATH", ndkLibclang)
            }
        }
        release.buildTaskProvider.configure {
            extraArguments.add("--locked")
            additionalEnvironment.put("CARGO_ENCODED_RUSTFLAGS", "--remap-path-prefix=$cargoHome=/cargo")
        }
    }
}

interface ExecOperationsHolder {
    @get:Inject
    val execOperations: ExecOperations
}

// `cargo install` ignores the lock file of what it installs unless told otherwise, and Gobley
// does not tell it: what generates the Kotlin bindings would be built from whatever its
// dependencies are that day. Installed first with the lock, Gobley's own install finds it
// there and does nothing. Only for F-Droid's build, Xcode's environment needing the clean-up
// Gobley gives its own command.
if (providers.gradleProperty("duckcount.fdroid").isPresent) {
    tasks.withType<InstallUniffiBindgenTask>().configureEach {
        val exec = objects.newInstance<ExecOperationsHolder>().execOperations
        val source = binaryCrateSource.map { it as CargoBinaryCrateSource.Registry }
        val root = installDirectory
        val hostTarget = GobleyHost.current.rustTarget.rustTriple
        val crateDirectory = projectDir

        doFirst {
            exec.exec {
                workingDir(crateDirectory)
                commandLine(
                    "cargo", "install", "--locked",
                    "--root", root.get().asFile.path,
                    "--target", hostTarget,
                    "${source.get().packageName}@${source.get().version}",
                )
            }
        }
    }
}
