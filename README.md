# SigmaDiff

## Dependency
- python                    3.9.7

- pytorch                   1.9.1

- gensim                    4.0.1

- scipy                     1.10.1

- torch-geometric           2.0.4

- numpy                     1.23.2

- ghidra                    9.2.2 or higher

- torch-scatter             2.0.9

- torch-sparse              0.6.12

**import json-simple-1.1.1.jar to ghidra**

json-simple-1.1.1.jar is located at ./ghidra_script. And we need to import it to ghidra in order to run VSAPCode.java. Please do the following steps:

Option 1:

Add jar to `<ghidra install dir>/Ghidra/patch/`.

Option 2:

1. create a new project called utils

![Alt text](image-1.png)

2. add the path to json-simple-1.1.1.jar in Edit->Plugin Path. Note that you need to use this project name (e.g., utils) later when running ghidra.

![Alt text](image-2.png)

For more information about importing third-parity jars to ghidra, please refer to:
https://github.com/NationalSecurityAgency/ghidra/issues/479


## Dataset
The sample dataset for Diffutils is located at ./data/binaries.
To obtain the complete dataset of our evaluation, you
can download it from: https://drive.google.com/drive/folders/1IimJi-03B4ljogtk4hli6B5G12MnpWJ-?usp=sharing.


## Run SigmaDiff
To test the sample data, update the ghidra-related locations, and run ./run.sh.

Otherwise, run python sigmadiff.py with specific arguments (see examples in run.sh).
To run stripped binaries, select the without ground truth, and the evaluation process will be skipped.

## Type Matrix
The type compatibility matrix we mentioned in paper is implemented in check_compatibility function in dgmc.py. In summary,

| Type    | Compatible With |
| -------- | ------- |
| undefined  | all types |
| undefined * | all types |
| void * | all types |
| undefined8 | long, ulong, double, size_t |
| undefined4 | float, int, wchar_t, uint |
| undefined2 | short, ushort |
| byte | char |
| long | ulong |
| short | ushort |
| int | uint |
| pointer type | other pointer types |