# ============================================
# Stage 1: 编译依赖库（不常变动，可被缓存）
# ============================================
FROM alpine:3.16 AS deps-builder
LABEL maintainer="tindy.it@gmail.com"
ARG THREADS="4"

WORKDIR /

# 安装构建工具和依赖
RUN apk add --no-cache git g++ build-base linux-headers cmake && \
    apk add --no-cache curl-dev rapidjson-dev pcre2-dev yaml-cpp-dev

# 编译 quickjspp（固定版本，几乎不变）
RUN set -xe && \
    git clone --no-checkout https://github.com/ftk/quickjspp.git && \
    cd quickjspp && \
    git fetch origin 0c00c48895919fc02da3f191a2da06addeb07f09 && \
    git checkout 0c00c48895919fc02da3f191a2da06addeb07f09 && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make quickjs -j $THREADS && \
    install -d /usr/lib/quickjs/ && \
    install -m644 quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -d /usr/include/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include && \
    cd .. && rm -rf quickjspp

# 编译 libcron（固定版本）
RUN set -xe && \
    git clone https://github.com/PerMalmberg/libcron --depth=1 && \
    cd libcron && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make libcron -j $THREADS && \
    install -m644 libcron/out/Release/liblibcron.a /usr/lib/ && \
    install -d /usr/include/libcron/ && \
    install -m644 libcron/include/libcron/* /usr/include/libcron/ && \
    install -d /usr/include/date/ && \
    install -m644 libcron/externals/date/include/date/* /usr/include/date/ && \
    cd .. && rm -rf libcron

# 编译 toml11（固定版本）
RUN set -xe && \
    git clone https://github.com/ToruNiina/toml11 --branch="v4.3.0" --depth=1 && \
    cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && \
    make install -j $THREADS && \
    cd .. && rm -rf toml11

# ============================================
# Stage 2: 编译 subconverter（经常变动）
# ============================================
FROM deps-builder AS app-builder
ARG THREADS="4"
ARG SHA=""

WORKDIR /

# 克隆并编译 subconverter
RUN set -xe && \
    apk add --no-cache python3 && \
    git clone https://github.com/Jacky-Bruse/subbehind subconverter --depth=1 && \
    cd subconverter && \
    if [ -n "$SHA" ]; then sed -i 's/\(v[0-9]\.[0-9]\.[0-9]\)/\1-'"$SHA"'/' src/version.h; fi && \
    python3 -m ensurepip && \
    python3 -m pip install gitpython && \
    python3 scripts/update_rules.py -c scripts/rules_config.conf && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make -j $THREADS

# ============================================
# Stage 3: 最终镜像
# ============================================
FROM alpine:3.16
LABEL maintainer="tindy.it@gmail.com"

RUN apk add --no-cache --virtual subconverter-deps pcre2 libcurl yaml-cpp

COPY --from=app-builder /subconverter/subconverter /usr/bin/
COPY --from=app-builder /subconverter/base /base/

ENV TZ=Africa/Abidjan
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /base
CMD subconverter

EXPOSE 25500/tcp
