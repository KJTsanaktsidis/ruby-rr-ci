FROM quay.io/fedora/fedora:40 AS sources

WORKDIR /root

# Relevant RPM building utilities
RUN <<BASHSCRIPT
  set -ex

  PACKAGES=(
    dnf-plugins-core    # Provides `dnf download` and `dnf-builddep`
    rpm-build           # Provies `rpmbuild` (used for unpacking srpms)
    rpmspectool         # Provides `rpmspec`
    patch               # We have some custom patches
    hostname            # Used in script below to set "email"
    git                 # We want `rr` straight from Git sources
    clang               # Must build ASAN libraries with Clang!
    compiler-rt         # clang asan dependency
    libzstd-devel       # `rr` dependency, not (yet?) covered by builddep rr
  )

  dnf update --refresh -y
  dnf install -y "${PACKAGES[@]}"
  dnf builddep -y openssl libyaml libffi rr

  git config --global user.name "ruby-rr-ci builder"
  git config --global user.email "ruby-rr-ci-builder@$(hostname)"

  mkdir /usr/local/asan
  mkdir /usr/local/asan/lib
BASHSCRIPT

RUN <<BASHSCRIPT
  set -ex

  # Download the OpenSSL SRPM, and unpack the sources
  dnf download --source openssl
  rpm -i openssl-*.src.rpm
  rm openssl-*.src.rpm
  cd ~/rpmbuild
  OPENSSL_VERSION="$(rpmspec --query --srpm  --qf "%{version}\n" SPECS/openssl.spec)"
  rpmbuild -bp SPECS/openssl.spec
  cd BUILD/openssl-$OPENSSL_VERSION

  mkdir build
  cd build
  # This is _mostly_ stolen from OpenSSL's spec file, but:
  #   - We build with enable-asan (that's what we're doing this for)
  #   - no-tests no-apps to avoid building stuff we don't need
  #   - -fno-lto to make it build faster
  #   - We use an RPATH to make sure other ASAN libraries are linked against too,
  #     in preference to system libraries
  #   - We disable the FIPS provider (it requires some annoying machinery around
  #     saving its own hash into the binary I can't be bothered getting right)
  #   - We build with Clang (CC=clang)
  #   - The $(rpm --eval) invocation passes the ordinary Clang CFLAGS/LDFLAGS
  #     used elsewhere in the distro
  ../Configure \
    --prefix=/usr \
    --openssldir=/etc/pki/tls \
    --system-ciphers-file=/etc/crypto-policies/back-ends/openssl.config \
    zlib enable-camellia enable-seed enable-rfc3779 enable-sctp \
    enable-cms enable-md2 enable-rc5 no-mdc2 no-ec2m no-sm2 no-sm4 \
    shared no-tests no-apps disable-fips \
    $(rpm --define 'toolchain clang' --eval "%{build_cflags} %{build_ldflags}") \
    CC=clang \
    -D_GNU_SOURCE -DPURIFY -O2 -ggdb3 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
    -fno-lto -Wl,--allow-multiple-definition -Wl,-rpath=/usr/local/asan/lib/
  make -j

  # Install the built shared objects into our ASAN directory
  install -v --mode=755 -t /usr/local/asan/lib libssl.so{,.3} libcrypto.so{,.3}

  # Clean up build (but not source) dir
  cd ..
  rm -Rf build
BASHSCRIPT

COPY libffi-unpoison-stack.patch .
RUN <<BASHSCRIPT
  set -ex

  # Download the libffi SRPM, and unpack the sources
  dnf download --source libffi
  rpm -i libffi-*.src.rpm
  rm libffi-*.src.rpm
  cd ~/rpmbuild
  LIBFFI_VERSION="$(rpmspec --query --srpm  --qf "%{version}\n" SPECS/libffi.spec)"
  rpmbuild -bp SPECS/libffi.spec
  cd BUILD/libffi-$LIBFFI_VERSION

  # libffi needs this patch not to crash under ASAN
  # See: https://github.com/libffi/libffi/pull/839
  patch -Np1 -i ~/libffi-unpoison-stack.patch

  mkdir build
  cd build

  ../configure \
    --prefix=/usr \
    --enable-shared \
    --enable-debug \
    CC=clang \
    CFLAGS="$(rpm --define 'toolchain clang' --eval "%{build_cflags} -fsanitize=address -fno-lto")" \
    LDFLAGS="$(rpm --define 'toolchain clang' --eval "%{build_ldflags} -fsanitize=address -fno-lto -Wl,-rpath=/usr/local/asan/lib")"
  make -j

  # Install the built shared objects into our ASAN directory
  install -v --mode=755 -t /usr/local/asan/lib .libs/libffi.so{,.*}

  # Clean up build (but not source) dir
  cd ..
  rm -Rf build
BASHSCRIPT

RUN <<BASHSCRIPT
  set -ex

  # Download the libyaml SRPM, and unpack the sources
  dnf download --source libyaml
  rpm -i libyaml-*.src.rpm
  rm libyaml-*.src.rpm
  cd ~/rpmbuild
  LIBYAML_VERSION="$(rpmspec --query --srpm  --qf "%{version}\n" SPECS/libyaml.spec)"
  rpmbuild -bp SPECS/libyaml.spec
  cd BUILD/yaml-$LIBYAML_VERSION

  mkdir build
  cd build

  ../configure \
    --prefix=/usr \
    --enable-shared \
    CC=clang \
    CFLAGS="$(rpm --define 'toolchain clang' --eval "%{build_cflags} -fsanitize=address -fno-lto")" \
    LDFLAGS="$(rpm --define 'toolchain clang' --eval "%{build_ldflags} -fsanitize=address -fno-lto -Wl,-rpath=/usr/local/asan/lib")"
  make -j

  # Install the built shared objects into our ASAN directory
  install -v --mode=755 -t /usr/local/asan/lib src/.libs/libyaml*.so{,.*}

  # Clean up build (but not source) dir
  cd ..
  rm -Rf build
BASHSCRIPT

COPY rr-scratch-mapping-flag.patch .
RUN <<BASHSCRIPT
  set -ex

  # There are at least four problems with `rr` as packaged in Fedora today:
  #
  #   1. https://github.com/rr-debugger/rr/issues/3364: the way that debug symbols are stripped
  #      mutilates librrpage.so
  #   2. https://github.com/rr-debugger/rr/issues/3772: we need fchmodat2 support, since glibc
  #      is definitely calling it
  #   3. https://github.com/rr-debugger/rr/issues/3773: LTO in librrpreload can move code around
  #      in a way it's not expecting and break it
  #   4. https://github.com/rr-debugger/rr/issues/3779: Ruby's extensive use of vfork shakes
  #      out a bug in signal stack handling during syscalls
  #
  # Issue no. 1 is a problem in the spec file Fedora is using to build rr. Issue 2 and 3 have
  # patches merged upstream that are not yet in Fedora, and issue 4 has a patch but it's not
  # merged upstream yet.
  #
  # So, compile our own RR from the (as of now) latest master.

  git clone --depth=1 https://github.com/rr-debugger/rr.git
  cd rr

  # This will start failing when the fix is merged upstream.
  git am ~/rr-scratch-mapping-flag.patch

  mkdir build
  cd build
  cmake \
    -DCMAKE_INSTALL_PREFIX:PATH=/usr/local \
    -DCMAKE_BUILD_TYPE=Release \
    -Ddisable32bit=ON \
    -DINSTALL_TESTSUITE=OFF \
    -DBUILD_TESTS=OFF \
    ..
  make -j
  make install

  cd ..
  rm -Rf build
BASHSCRIPT

FROM quay.io/fedora/fedora:40

COPY --from=sources /usr/local /usr/local
RUN <<BASHSCRIPT
  PACKAGES=(
    # Compilers
    clang compiler-rt
    # BASERUBY
    ruby-devel
    # Ruby's build dependency libraries
    # Need the -devel versions, even though we have copies in /usr/local/asan, because
    # we didn't copy the headers there.
    openssl-devel libyaml-devel libffi-devel
    readline-devel gdbm-devel zlib-ng-devel
    # `rr`s dependencies - they won't be automatically downloaded by anything
    libzstd capnproto 
    # Other nescessary utilities
    git wget hostname
    # We don't need this to _run_ the tests, but it's convenient to be able to replay
    # them in this container, so include GDB in here too.
    gdb
  )
  dnf update --refresh -y
  dnf install -y "${PACKAGES[@]}"

  git config --global user.name "ruby-rr-ci builder"
  git config --global user.email "ruby-rr-ci-builder@$(hostname)"
BASHSCRIPT
