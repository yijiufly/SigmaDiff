home=`pwd`
export LD_LIBRARY_PATH="/home/administrator/.conda/envs/myenv/lib:$LD_LIBRARY_PATH"
echo $home
cd data/binaries
version1=diffutils-2.8-O0
version2=diffutils-2.8-O3
cd $version1
rm *stripped
binlst=`ls`
for binaryfile in $binlst
do
    cd $home
    python sigmadiff.py --input1 $home/data/binaries/$version1/$binaryfile --input2 $home/data/binaries/$version2/$binaryfile --ghidra_home /home/administrator/Downloads/Lian/ghidra_9.2.2_PUBLIC --output_dir $home/out --with_gt True
done