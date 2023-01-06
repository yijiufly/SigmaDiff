1: 
2: undefined8 FUN_001254e0(long param_1)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: uint uVar3;
8: bool bVar4;
9: 
10: ppcVar2 = *(code ***)(param_1 + 0x220);
11: if (*(int *)(param_1 + 0x24) != 0xcc) {
12: (**ppcVar2)();
13: ppcVar2 = *(code ***)(param_1 + 0x220);
14: *(undefined4 *)(param_1 + 0xa8) = 0;
15: *(undefined4 *)(param_1 + 0x24) = 0xcc;
16: }
17: if (*(int *)(ppcVar2 + 2) != 0) {
18: uVar3 = *(uint *)(param_1 + 0xa8);
19: do {
20: while (uVar1 = *(uint *)(param_1 + 0x8c), uVar3 < uVar1) {
21: ppcVar2 = *(code ***)(param_1 + 0x10);
22: if (ppcVar2 == (code **)0x0) {
23: (**(code **)(*(long *)(param_1 + 0x228) + 8))(param_1,0,param_1 + 0xa8);
24: bVar4 = *(uint *)(param_1 + 0xa8) == uVar3;
25: uVar3 = *(uint *)(param_1 + 0xa8);
26: if (bVar4) {
27: return 0;
28: }
29: }
30: else {
31: ppcVar2[1] = (code *)(ulong)uVar3;
32: ppcVar2[2] = (code *)(ulong)uVar1;
33: (**ppcVar2)(param_1);
34: uVar1 = *(uint *)(param_1 + 0xa8);
35: (**(code **)(*(long *)(param_1 + 0x228) + 8))(param_1,0,param_1 + 0xa8);
36: uVar3 = *(uint *)(param_1 + 0xa8);
37: if (*(uint *)(param_1 + 0xa8) == uVar1) {
38: return 0;
39: }
40: }
41: }
42: (**(code **)(*(long *)(param_1 + 0x220) + 8))(param_1);
43: (***(code ***)(param_1 + 0x220))(param_1);
44: *(undefined4 *)(param_1 + 0xa8) = 0;
45: uVar3 = 0;
46: } while (*(int *)(*(long *)(param_1 + 0x220) + 0x10) != 0);
47: }
48: *(uint *)(param_1 + 0x24) = (*(int *)(param_1 + 0x5c) != 0) + 0xcd;
49: return 1;
50: }
51: 
