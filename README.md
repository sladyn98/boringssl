# BoringSSL


[![Build Status](https://aussie-1.lf-dev.marist.edu:9443/buildStatus/icon?job=omp-btls)](https://aussie-1.lf-dev.marist.edu:9443/job/omp-btls/)

The jenkins build runs on the above url.
The builds run every 5 hours.
The commands used to build the project are:
```
mkdir build
cd build
cmake3 ..
make
```

These commands can be run from the root directory.

OMP-19

This fork has been developed to run cryptographic libraries using hardware acceleration.

Mentor:
* [Neale](https://github.com/nealef)

Student:
* [Sladyn](https://github.com/sladyn98)
BoringSSL is a fork of OpenSSL that is designed to meet Google's needs.

Although BoringSSL is an open source project, it is not intended for general
use, as OpenSSL is. We don't recommend that third parties depend upon it. Doing
so is likely to be frustrating because there are no guarantees of API or ABI
stability.

Programs ship their own copies of BoringSSL when they use it and we update
everything as needed when deciding to make API changes. This allows us to
mostly avoid compromises in the name of compatibility. It works for us, but it
may not work for you.

BoringSSL arose because Google used OpenSSL for many years in various ways and,
over time, built up a large number of patches that were maintained while
tracking upstream OpenSSL. As Google's product portfolio became more complex,
more copies of OpenSSL sprung up and the effort involved in maintaining all
these patches in multiple places was growing steadily.

Currently BoringSSL is the SSL library in Chrome/Chromium, Android (but it's
not part of the NDK) and a number of other apps/programs.

There are other files in this directory which might be helpful:

  * [PORTING.md](/PORTING.md): how to port OpenSSL-using code to BoringSSL.
  * [BUILDING.md](/BUILDING.md): how to build BoringSSL
  * [INCORPORATING.md](/INCORPORATING.md): how to incorporate BoringSSL into a project.
  * [API-CONVENTIONS.md](/API-CONVENTIONS.md): general API conventions for BoringSSL consumers and developers.
  * [STYLE.md](/STYLE.md): rules and guidelines for coding style.
  * include/openssl: public headers with API documentation in comments. Also [available online](https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html).
  * [FUZZING.md](/FUZZING.md): information about fuzzing BoringSSL.
  * [CONTRIBUTING.md](/CONTRIBUTING.md): how to contribute to BoringSSL.
  * [BREAKING-CHANGES.md](/BREAKING-CHANGES.md): notes on potentially-breaking changes.
