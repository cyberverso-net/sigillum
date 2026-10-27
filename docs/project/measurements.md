# Measurements for goal G4

This document sets the protocol for measuring signing latency, memory and binary size, so that the targets of goal G4 in the [charter](charter.md) rest on comparable figures. The same protocol applies to the reference stacks and, later, to sigillum. DSS on a JVM is measured in phase 0, and the EUDI reference stack on Android and iOS at the start of phase 1. The results are recorded in this document, under *Results*, as they are produced.

## Operations

Signing is split into two steps, as described in [ADR-0005](../design/adr/0005-two-step-signing.md). Each step is measured on its own:

| Operation | Input | Output |
| --- | --- | --- |
| PAdES prepare | A PDF document of 1 MB, and one of 20 MB, with the signer's certificate chain | The data to be signed, and the state needed to finish the signature |
| PAdES assemble | The prepared state and a supplied signature value | The signed PDF document |
| CAdES detached prepare | The same 1 MB and 20 MB documents, as binary content | The data to be signed, and the state needed to finish the signature |
| CAdES detached assemble | The prepared state and a supplied signature value | The detached CAdES signature |

In this document, 1 MB is 1,000,000 bytes and 20 MB is 20,000,000 bytes.

An operation that a stack does not provide is recorded as "not provided" and is not replaced by another operation. The signing stack of the EUDI Wallet reference implementation, for example, provides no CAdES.

### Fixed parameters

- **Level.** Signatures are created at baseline level B-B, so that no timestamp or revocation retrieval is involved. A stack that cannot create B-B is reported as a deviation, with any timestamp source replaced by a local stub, and its figures are marked as such. The signed attributes each stack produces are recorded, so that the work done can be compared.
- **Signing time and other variable fields.** The signing time is fixed. Where the stack allows, so are the other fields that would change the data to be signed between runs, such as the document identifier and the dates written by a PAdES incremental update.
- **Prepared state and signature value.** One prepare run is made outside the timed section, and its data to be signed is signed once with a test key. Every timed assemble run reuses that prepared state and signature value. Where a stack's prepared state cannot be reused, each assemble run is preceded, outside the timed section, by its own prepare run and signature.
- **Input in memory.** The input document is read into memory before timing starts, so file input and output are excluded. The output is kept in memory.

### Stacks that cannot separate the steps

A stack whose signing call cannot be split is measured as one call with a local test key. The private-key operation is then timed on its own with the same key and reported next to the result. The result is marked as not directly comparable with prepare plus assemble. A stack that separates the steps through a session held in memory, rather than the serialisable state of ADR-0005, is measured step by step, and the difference is noted.

## Inputs

The input documents are generated reproducibly, so that every stack signs the same bytes:

- **Structure.** Each PDF document follows ISO 32000-1:2008, with uncompressed content streams, a classic cross-reference table and no existing signatures. Its pages contain only text in a standard font. The 1 MB and 20 MB files differ only in their number of pages, chosen to reach the stated size. A padding comment at the end of the last content stream makes the size exact.
- **CAdES content.** The binary content for CAdES is the same PDF file read as bytes.
- **Signer.** The signer's certificate chain and key come from the project's test PKI ([ADR-0014](../design/adr/0014-test-pki-and-corpus.md)), with an ECDSA P-256 key and certificate.

The generator and its parameters are recorded with the first results. The SHA-256 digests of the input files are recorded in this document once they are generated, and every result refers to them.

## Metrics

### Latency

The wall-clock time of one operation, measured inside the process with a monotonic clock around the call.

- **Warm-up.** On a JVM, warm-up runs continue until the median of the last 20 runs is within 2% of that of the previous 20, so that just-in-time compilation has settled. The warm-up stops after 2,000 runs at most, and figures that have not settled by then are reported as such. [JMH](https://github.com/openjdk/jmh) may be used instead. On native stacks, at least 10 warm-up runs are made.
- **Runs.** At least 100 timed runs for the 1 MB documents and at least 30 for the 20 MB documents.
- **Figures.** The median, the 95th percentile by the nearest-rank method, the minimum, the maximum and the interquartile range.
- **Cold call.** The first call in a fresh process is reported as a separate figure, because it is what a mobile user experiences. For assemble, it is the first assemble call after the prepared state has been loaded. Where the state cannot be saved, the cold assemble call follows a prepare in the same process and is marked as such. On a JVM, start-up time, from process start to the start of `main`, is reported separately as well.

The timed runs are repeated in a second session. If the medians of the two sessions differ by more than 10%, the person running the measurement looks for the cause. Figures whose difference cannot be explained are reported with it, and are not used to set targets.

### Peak memory

The peak memory of a fresh process that runs one operation on one input size, read inside the process from one high-water-mark counter per platform:

| Platform | Counter |
| --- | --- |
| Linux | `VmHWM` in `/proc/self/status` (peak resident set, including shared pages) |
| Android | `VmHWM` in `/proc/self/status` (as on Linux; it includes runtime pages shared with other applications) |
| macOS and iOS | `ledger_phys_footprint_peak` from `task_info` with `TASK_VM_INFO` (the peak of the footprint that iOS uses to limit applications) |

The desktop machine runs Linux or macOS.

The counter is read once the process has loaded its inputs and before the first measured operation, and again after the last run; the difference is reported, with both values. For assemble, the prepared state and the signature value are produced by a separate process and loaded before the first reading, so that the prepare step does not hide the peak of assemble. Where the state cannot be saved, one combined peak for prepare and assemble is reported and marked as such. On a JVM, the heap settings and the garbage collector are recorded, and the peak heap use is reported as well.

### Binary size

The size that the signing stack adds to an otherwise empty application, built in release mode:

| Platform | How it is measured |
| --- | --- |
| Android | An Android App Bundle built with and without the stack, turned into an APK set with `bundletool build-apks`, and measured with `bundletool get-size total` for a device specification with the `arm64-v8a` ABI only. This gives download sizes. Whether code shrinking (R8) is enabled is recorded |
| iOS | The App Thinning Size Report of Xcode for the recorded iPhone model, with and without the stack |
| Desktop JVM | The minimal set of JAR files needed for the operations, uncompressed and compressed, with the Java runtime noted as excluded |
| Desktop native | The size of the stripped executable with and without the stack |

Each figure states whether it is a download (compressed) or an install (uncompressed) size.

## Devices

| Device class | What is recorded |
| --- | --- |
| One mid-range Android device | Manufacturer, model, Android version, CPU, memory |
| One iPhone | Model, iOS version, CPU and memory as published for the model |
| One desktop machine | Manufacturer and model, operating system and version, CPU, memory |

During measurement, mobile devices have at least 80% battery and are not charging. Battery saver or Low Power Mode is off, airplane mode is on, and no other application is in the foreground. Every device runs release builds.

DSS is measured on the desktop machine only, because it does not run on iOS and the EUDI reference implementation does not use it on Android. The EUDI stack is measured on the mobile devices only. Comparisons between these stacks are therefore indirect, through sigillum's own figures on every device.

## What is excluded

- Network time, including the call to a remote signing service, which [ADR-0005](../design/adr/0005-two-step-signing.md) places outside the library.
- The private-key operation, except where it is timed on its own as described above.
- Retrieval of timestamps, certificates and revocation data, which the fixed level avoids.
- File input and output, and the start-up time of a runtime, which is reported separately where it applies.

## Reproducing a result

Every result records:

1. the stack and its version, and the version of each library it depends on;
2. the runtime and build settings: the vendor, version and flags of a JVM; the build configuration, minimum SDK, ABI and R8 setting on Android; the Xcode and Swift versions and build settings on iOS;
3. the device, as described under *Devices*;
4. the signature level, the signed attributes produced, and whether the steps were measured separately;
5. the SHA-256 digests of the input files;
6. the commit of this repository whose harness produced the figures, and the commands used to build and run it, from `tools/measurements/dss`, `tools/measurements/android` or `tools/measurements/ios`;
7. the raw timings and memory readings of every run, kept with the harness output.

A result is reproduced by building and running the same harness at the same commit with the same commands and inputs, on the same device model and operating system version.

## Results

No measurements have been made yet. Results for DSS on a JVM, and for the signing stack of the EUDI Wallet reference implementation on Android and on iOS, will be added here.
