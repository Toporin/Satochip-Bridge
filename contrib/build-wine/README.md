Windows binaries
================

**Work in progress: currently, the binaries generated are not deterministic! ** 

** These scripts are for building windows binaries on Linux.  See the folder 'build-windows' for windows script**

✓ _These binaries should be reproducible, meaning you should be able to generate
   binaries that match the official releases._

This assumes an Ubuntu (x86_64) host, but it should not be too hard to adapt to another
similar system. The docker commands should be executed in the project's root
folder.

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ sudo docker build -t electrum-wine-builder-img contrib/build-wine
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

3. Build Windows binaries

    It's recommended to build from a fresh clone
    (but you can skip this if reproducibility is not necessary).

    ```
    $ FRESH_CLONE=contrib/build-wine/fresh_clone && \
        sudo rm -rf $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/spesmilo/electrum.git && \
        cd electrum
    ```

    And then build from this directory:
    ```
    $ git checkout $REV
    $ sudo docker run -it \
        --name electrum-wine-builder-cont \
        -v $PWD:/opt/wine64/drive_c/electrum \
        --rm \
        --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
        electrum-wine-builder-img \
        ./build.sh
    ```
4. The generated binaries are in `./contrib/build-wine/dist`.

