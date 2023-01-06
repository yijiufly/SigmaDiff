1: 
2: void FUN_0011c120(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: 
10: pcVar2 = param_1[0x39];
11: pcVar4 = pcVar2;
12: if (param_2 != 2) {
13: ppcVar3 = (code **)*param_1;
14: *(undefined4 *)(ppcVar3 + 5) = 4;
15: (**ppcVar3)();
16: pcVar4 = param_1[0x39];
17: }
18: iVar1 = *(int *)((long)param_1 + 0x144);
19: *(undefined4 *)(pcVar2 + 0x10) = 0;
20: if (iVar1 < 2) {
21: if (*(uint *)(pcVar4 + 0x10) < *(int *)(param_1 + 0x28) - 1U) {
22: *(undefined4 *)(pcVar4 + 0x1c) = *(undefined4 *)(param_1[0x29] + 0xc);
23: }
24: else {
25: *(undefined4 *)(pcVar4 + 0x1c) = *(undefined4 *)(param_1[0x29] + 0x48);
26: }
27: }
28: else {
29: *(undefined4 *)(pcVar4 + 0x1c) = 1;
30: }
31: *(undefined4 *)(pcVar4 + 0x14) = 0;
32: *(undefined4 *)(pcVar4 + 0x18) = 0;
33: return;
34: }
35: 
