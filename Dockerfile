FROM quay.io/fedora/fedora:40

WORKDIR /root

# Relevant RPM building utilities
RUN <<BASHSCRIPT
  set -ex

  PACKAGES=(
    # Provides `dnf download` and `dnf-builddep`
    dnf-plugins-core
    # Provies `rpmbuild` (used for unpacking srpms) and rpmspec
    rpm-build rpmspectool
    # LLVM toolchain (compiler-rt for ASAN, rust for YJIT)
    # (nope - see below - using nightly)
    # clang compiler-rt
    # BASERUBY
    ruby-devel ruby-default-gems ruby-bundled-gems rubygem-rexml
    # Ruby build system deps
    make autoconf diffutils gperf
    # Ruby's build dependency libraries
    # Need the -devel versions, even though we have copies in /usr/local/asan, because
    # we didn't copy the headers there.
    openssl-devel libyaml-devel libffi-devel
    readline-devel gdbm-devel zlib-ng-devel
    zlib-ng-compat-devel libcap-devel
    # `rr`s dependencies - they won't be automatically downloaded by anything
    libzstd-devel capnproto-devel
    # We don't need this to _run_ the tests, but it's convenient to be able to replay
    # them in this container, so include GDB in here too.
    gdb
    # General build tools we need
    patch git wget curl
    # Misc junk draw
    hostname procps-ng bash
    # pernosco
    python3 awscli openssl
    # Tools for entrypoint script
    libcap libcgroup-tools dumb-init util-linux
  )

  dnf update --refresh -y
  dnf install -y "${PACKAGES[@]}"
  dnf builddep -y openssl libyaml libffi rr

  # Nightly Clang is required, it seems (??)
  dnf copr enable -y @fedora-llvm-team/llvm-snapshots
  dnf install --refresh -y clang compiler-rt

  # Now _carefully_ install rust with llvm18
  dnf install -y rust llvm18-libs

  git config --global user.name "ruby-rr-ci builder"
  git config --global user.email "ruby-rr-ci-builder@$(hostname)"

  mkdir /usr/local/asan
  mkdir /usr/local/asan/lib

  mkdir -p ~/patches
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

  cd ../..
  rm -Rf openssl-$OPENSSL_VERSION
BASHSCRIPT

COPY patches/libffi/ patches/libffi/
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
  for PATCH in ~/patches/libffi/*.patch; do
    patch -Np1 -i "$PATCH";
  done;

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

  cd ../..
  rm -Rf libffi-$LIBFFI_VERSION
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

  cd ../..
  rm -Rf yaml-$LIBYAM_VERSION
BASHSCRIPT

COPY patches/rr/ patches/rr/
RUN <<BASHSCRIPT
  set -ex

  # There are at least eight problems with `rr` as packaged in Fedora today:
  #
  #   1. https://github.com/rr-debugger/rr/issues/3364: the way that debug symbols are stripped
  #      mutilates librrpage.so
  #   2. https://github.com/rr-debugger/rr/issues/3772: we need fchmodat2 support, since glibc
  #      is definitely calling it
  #   3. https://github.com/rr-debugger/rr/issues/3773: LTO in librrpreload can move code around
  #      in a way it's not expecting and break it
  #   4. https://github.com/rr-debugger/rr/issues/3779: Ruby's extensive use of vfork shakes
  #      out a bug in signal stack handling during syscalls
  #   5. https://github.com/rr-debugger/rr/issues/3807: vfork again shakes out a nasty deadlock
  #      when rr tries to unmap the exec'd processes address space.
  #   6. https://github.com/rr-debugger/rr/pull/3855: New clang moved the location of the ASAN
  #      shadow stack, and rr needs to know about it.
  #   7. https://github.com/rr-debugger/rr/pull/3856: Chaos mode can put mappings in places where
  #      its VMA gets merged with the stack VMA, and confuses glibc.
  #   8. https://github.com/rr-debugger/rr/pull/3874: A problem in SIGSTOP/SIGCONT hangling
  #      that affects Ruby's TestSignal#test_stop_self test.
  #
  # Issue no. 1 is a problem in the spec file Fedora is using to build rr. The rest have patches
  # merged upstream that are not yet in Fedora.
  #
  # So, compile our own RR from the (as of now) latest master.

  git clone --depth=1 https://github.com/rr-debugger/rr.git
  cd rr

  shopt -s nullglob;
  for PATCH in ~/patches/rr/*.patch; do
    patch -Np1 -i "$PATCH";
  done;

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

  cd ../..
  rm -Rf rr
BASHSCRIPT

RUN <<BASHSCRIPT
  set -ex;
  cd /usr/local
  mkdir -p share
  cd share
  git clone https://github.com/Pernosco/pernosco-submit
  cd ../bin
  ln -svf ../share/pernosco-submit/pernosco-submit pernosco-submit
BASHSCRIPT

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
