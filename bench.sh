#!/bin/sh

# ask to delete old benchmarks if they are present
bench="bench.txt"
if [ -f $bench ]; then
    rm -i $bench
fi

# benchmarks
ped_iters=10
sha_iters=5
schemes="sonic lamassu bb-lamassu"
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

    ### header
    set -f
    echo "*****************************************************************" >> $bench
    echo $header >> $bench
    echo "*****************************************************************" >> $bench
    set +f

    ### Pedersen: 48, 384
    echo "_____________________________Pedersen____________________________" >> $bench
    for bitsize in 48 384
    do
        cargo run --example $scheme pedersen $bitsize $ped_iters
        echo >> $bench
    done

    ### SHA256: 512, 1024, 2048?
    echo "______________________________SHA256_____________________________" >> $bench
    for bitsize in 512 1024 #2048
    do
        cargo run --example $scheme sha256 $bitsize $sha_iters
        echo >> $bench
    done
done