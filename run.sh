home=`pwd`
# export path/to/conda/env/lib if missing some .so
# export LD_LIBRARY_PATH="/home/administrator/.conda/envs/myenv/lib:$LD_LIBRARY_PATH"

# replace with your path to ghidra
ghidra_home=/home/administrator/Downloads/Lian/ghidra_9.2.2_PUBLIC

# the created project name, e.g., utils
ghidra_proj_name=utils

echo "version, precision, recall, f1-score, avg_time" >> $home/out/finalresults.txt
echo "compared binary, time, size, f1-score" >> $home/out/time.txt

# cross compiler evaluation
version1=coreutils-8.1-clang
version2=coreutils-8.1-x86
python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name


# cross arch evaluation
version1=coreutils-8.1-arm
version2=coreutils-8.1-x86
python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name

# cross opt level evaluation
version2=coreutils-5.93-O3
for version1 in coreutils-5.93-O0 coreutils-5.93-O1 coreutils-5.93-O2
do
    python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name
done

# cross version evaluation
version2=coreutils-8.1-O2
for version1 in coreutils-5.93-O2 coreutils-6.4-O2
do
    python sigmadiff.py --input1 $home/data/binaries/$version1 --input2 $home/data/binaries/$version2 --ghidra_home $ghidra_home --output_dir $home/out --with_gt --src_dir $home/data/sources --ghidra_proj_name $ghidra_proj_name
done