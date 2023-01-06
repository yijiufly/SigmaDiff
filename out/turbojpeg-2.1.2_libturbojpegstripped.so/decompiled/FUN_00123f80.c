1: 
2: void FUN_00123f80(code **param_1,int param_2)
3: 
4: {
5: undefined4 uVar1;
6: int iVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: 
11: pcVar3 = param_1[0x39];
12: pcVar5 = pcVar3;
13: if (param_2 != 2) {
14: ppcVar4 = (code **)*param_1;
15: *(undefined4 *)(ppcVar4 + 5) = 4;
16: (**ppcVar4)();
17: pcVar5 = param_1[0x39];
18: }
19: iVar2 = *(int *)((long)param_1 + 0x144);
20: *(undefined4 *)(pcVar3 + 0x10) = 0;
21: if (iVar2 < 2) {
22: if (*(uint *)(pcVar5 + 0x10) < *(int *)(param_1 + 0x28) - 1U) {
23: uVar1 = *(undefined4 *)(param_1[0x29] + 0xc);
24: *(undefined8 *)(pcVar5 + 0x14) = 0;
25: *(undefined4 *)(pcVar5 + 0x1c) = uVar1;
26: return;
27: }
28: uVar1 = *(undefined4 *)(param_1[0x29] + 0x48);
29: *(undefined8 *)(pcVar5 + 0x14) = 0;
30: *(undefined4 *)(pcVar5 + 0x1c) = uVar1;
31: return;
32: }
33: *(undefined4 *)(pcVar5 + 0x1c) = 1;
34: *(undefined8 *)(pcVar5 + 0x14) = 0;
35: return;
36: }
37: 
