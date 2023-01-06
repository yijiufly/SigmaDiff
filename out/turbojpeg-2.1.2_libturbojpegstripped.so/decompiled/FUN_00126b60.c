1: 
2: void FUN_00126b60(code **param_1,undefined8 param_2)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: undefined8 uVar3;
8: undefined8 *puVar4;
9: 
10: puVar4 = (undefined8 *)param_1[5];
11: if (puVar4 == (undefined8 *)0x0) {
12: pcVar2 = (code *)(**(code **)param_1[1])(param_1,0,0x50);
13: param_1[5] = pcVar2;
14: uVar3 = (**(code **)param_1[1])(param_1,0,0x1000);
15: *(undefined8 *)(pcVar2 + 0x40) = uVar3;
16: puVar4 = (undefined8 *)param_1[5];
17: }
18: else {
19: if ((code *)puVar4[2] != FUN_00126a10) {
20: ppcVar1 = (code **)*param_1;
21: *(undefined4 *)(ppcVar1 + 5) = 0x17;
22: (**ppcVar1)();
23: puVar4 = (undefined8 *)param_1[5];
24: }
25: }
26: puVar4[2] = FUN_00126a10;
27: puVar4[7] = param_2;
28: puVar4[3] = FUN_00126ac0;
29: puVar4[6] = FUN_00126b50;
30: puVar4[5] = FUN_00136850;
31: puVar4[1] = 0;
32: puVar4[4] = FUN_00126a70;
33: *puVar4 = 0;
34: return;
35: }
36: 
