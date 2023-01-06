1: 
2: void FUN_00126880(code **param_1,undefined8 param_2)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: 
8: pcVar2 = param_1[5];
9: if (pcVar2 == (code *)0x0) {
10: pcVar2 = (code *)(**(code **)param_1[1])(param_1,0,0x38);
11: param_1[5] = pcVar2;
12: }
13: else {
14: if (*(code **)(pcVar2 + 0x10) != FUN_001266a0) {
15: ppcVar1 = (code **)*param_1;
16: *(undefined4 *)(ppcVar1 + 5) = 0x17;
17: (**ppcVar1)();
18: pcVar2 = param_1[5];
19: }
20: }
21: *(code **)(pcVar2 + 0x10) = FUN_001266a0;
22: *(undefined8 *)(pcVar2 + 0x28) = param_2;
23: *(code **)(pcVar2 + 0x18) = FUN_00126700;
24: *(code **)(pcVar2 + 0x20) = FUN_00126760;
25: return;
26: }
27: 
