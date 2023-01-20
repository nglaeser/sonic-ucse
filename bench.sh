#!/bin/sh

# ask to delete old benchmarks if they are present
bench="bench.txt"
if [ -f $bench ]; then
    rm -i $bench
fi

# benchmarks
ped_iters=20
sha_iters=10
schemes="sonic lamassu bb-lamassu"
ped_bitsizes="48 384"
sha_bitsizes="512 1024 2048"
for scheme in $schemes
do
    case $scheme in
        "sonic")
            header="****************************** Sonic *****************************"
            ;;
        "lamassu")
            header="**************************** Lamassu ****************************"
            ;;
        "bb-lamassu")
            header="************************** BB-Lamassu ***************************"
            ;;
    esac
    if [ -z "$ped_bitsizes" ] && [ -z $sha_bitsizes ]; then
        # if both ped and sha bitsizes to run are empty, skip to next scheme
        continue
    fi

    ### header
    set -f
    echo "*****************************************************************" >> $bench
    echo $header >> $bench
    echo "*****************************************************************" >> $bench
    set +f

    ### Pedersen: 48, 384
    if [ -n "$ped_bitsizes" ]; then
        # ped_bitsizes is not empty
        echo "_____________________________Pedersen____________________________" >> $bench
        for bitsize in $ped_bitsizes
        do
            cargo run -r --example $scheme pedersen $bitsize $ped_iters
            echo >> $bench
        done
    fi

    ### SHA256: 512, 1024, 2048?
    if [ -n "$sha_bitsizes" ]; then
        # sha_bitsizes is not empty
        echo "______________________________SHA256_____________________________" >> $bench
        for bitsize in $sha_bitsizes
        do
            cargo run -r --example $scheme sha256 $bitsize $sha_iters
            echo >> $bench
        done
    fi
done