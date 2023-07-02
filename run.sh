home=`pwd`
# export path/to/conda/env/lib if missing some .so
export LD_LIBRARY_PATH="/home/administrator/.conda/envs/myenv/lib:$LD_LIBRARY_PATH"

# replace with your path to ghidra
ghidra_home=/home/administrator/Downloads/Lian/ghidra_9.2.2_PUBLIC

# the created project name, e.g., utils
ghidra_proj_name=utils

echo "version, precision, recall, f1-score, time" >> $home/out/finalresults.txt

# cross version evaluation
version2=diffutils-3.6-O2
for version1 in diffutils-2.8-O2 diffutils-3.4-O2
do
    python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt True --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name
done

# cross opt level evaluation
version2=diffutils-3.4-O3
for version1 in diffutils-3.4-O0 diffutils-3.4-O1 diffutils-3.4-O2
do
    python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt True --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name
done

version2=diffutils-3.6-O3
for version1 in diffutils-3.6-O0 diffutils-3.6-O1 diffutils-3.6-O2
do
    python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt True --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name
done

# cross compiler evaluation
version1=diffutils-3.6-clang
version2=diffutils-3.6-x86
python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt True --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name

# cross arch evaluation
version1=diffutils-3.6-arm
version2=diffutils-3.6-x86
python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt True --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name