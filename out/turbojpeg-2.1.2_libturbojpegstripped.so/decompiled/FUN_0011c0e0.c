1: 
2: void FUN_0011c0e0(code **param_1,int param_2)
3: 
4: {
5: code *pcVar1;
6: 
7: if (*(int *)(param_1 + 0x20) == 0) {
8: pcVar1 = param_1[0x37];
9: if (param_2 != 0) {
10: param_1 = (code **)*param_1;
11: *(undefined4 *)(param_1 + 5) = 4;
12: (**param_1)();
13: }
14: *(undefined8 *)(pcVar1 + 0x10) = 0;
15: *(undefined4 *)(pcVar1 + 0x18) = 0;
16: *(int *)(pcVar1 + 0x1c) = param_2;
17: *(code **)(pcVar1 + 8) = FUN_0011c140;
18: return;
19: }
20: return;
21: }
22: 
