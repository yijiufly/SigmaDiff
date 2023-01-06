1: 
2: void FUN_00112750(code **param_1,int param_2)
3: 
4: {
5: code *pcVar1;
6: 
7: pcVar1 = param_1[0x37];
8: if (*(int *)(param_1 + 0x20) == 0) {
9: if (param_2 != 0) {
10: param_1 = (code **)*param_1;
11: *(undefined4 *)(param_1 + 5) = 4;
12: (**param_1)();
13: }
14: *(undefined4 *)(pcVar1 + 0x10) = 0;
15: *(undefined4 *)(pcVar1 + 0x14) = 0;
16: *(undefined4 *)(pcVar1 + 0x18) = 0;
17: *(int *)(pcVar1 + 0x1c) = param_2;
18: *(code **)(pcVar1 + 8) = FUN_001127b0;
19: }
20: return;
21: }
22: 
