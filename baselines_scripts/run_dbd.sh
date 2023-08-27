# coreutils
mkdir DeepBinDiff_out
for v in 5.93 6.4
do
    for opt in O0 O1 O2
    do
        # enter deepbindiff dir
        cd /path/to/DBD
        ./src/analysis_in_batch.sh data/binaries/coreutils-$v-$opt/ data/binaries/coreutils-$v-O3/ DeepBinDiff_out/coreutils-$v-$opt\_vs_coreutils-$v-O3/
    done
done
