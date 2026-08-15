FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git wget unzip \
    virtualenvwrapper python3-dev python3-pip python-is-python3 python3-venv \
    openjdk-21-jdk \
    clang-15 lld-15 \
    qemu-user \
    gcc-multilib \
    libc6-dev-armhf-cross libc6-dev-arm64-cross \
    libc6-dev-mips-cross libc6-dev-mips64-cross \
    libc6-dev-powerpc-cross libc6-dev-ppc64-cross \
    libc6-dev-mipsel-cross libc6-dev-mips64el-cross \
    libc6-dev-ppc64el-cross libc6-dev-s390x-cross \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
    && echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main" | tee /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y clang-19 lld-19 \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip \
    && unzip /ghidra_12.1.2_PUBLIC_20260605.zip

ENV GHIDRA_INSTALL_DIR=/ghidra_12.1.2_PUBLIC

COPY . /patcherex2

RUN pip install -U pip pytest ruff
RUN pip install -e /patcherex2[all]

CMD ["/bin/bash"]
