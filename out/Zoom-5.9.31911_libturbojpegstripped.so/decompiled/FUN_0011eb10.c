1: 
2: void FUN_0011eb10(code **param_1,undefined8 param_2)
3: 
4: {
5: code **ppcVar1;
6: undefined8 *puVar2;
7: code *pcVar3;
8: undefined8 uVar4;
9: 
10: puVar2 = (undefined8 *)param_1[5];
11: if (puVar2 == (undefined8 *)0x0) {
12: pcVar3 = (code *)(**(code **)param_1[1])(param_1,0,0x50);
13: param_1[5] = pcVar3;
14: uVar4 = (**(code **)param_1[1])(param_1,0,0x1000);
15: *(undefined8 *)(pcVar3 + 0x40) = uVar4;
16: puVar2 = (undefined8 *)param_1[5];
17: }
18: else {
19: if ((code *)puVar2[2] != FUN_0011e9b0) {
20: ppcVar1 = (code **)*param_1;
21: *(undefined4 *)(ppcVar1 + 5) = 0x17;
22: (**ppcVar1)();
23: puVar2 = (undefined8 *)param_1[5];
24: }
25: }
26: puVar2[7] = param_2;
27: puVar2[1] = 0;
28: puVar2[2] = FUN_0011e9b0;
29: puVar2[3] = FUN_0011ea70;
30: puVar2[4] = FUN_0011ea10;
31: puVar2[5] = FUN_0012b9a0;
32: puVar2[6] = FUN_0011ea60;
33: *puVar2 = 0;
34: return;
35: }
36: 
