1: 
2: void FUN_001249b0(code **param_1,code *param_2)
3: 
4: {
5: code **ppcVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: uint uVar4;
9: int iVar5;
10: bool bVar6;
11: 
12: iVar5 = *(int *)((long)param_1 + 0x24);
13: if (iVar5 != 100) {
14: ppcVar2 = (code **)*param_1;
15: *(undefined4 *)(ppcVar2 + 5) = 0x14;
16: *(int *)((long)ppcVar2 + 0x2c) = iVar5;
17: (**ppcVar2)();
18: }
19: FUN_00102c80(param_1,0);
20: (**(code **)(*param_1 + 0x20))(param_1);
21: (**(code **)(param_1[5] + 0x10))(param_1);
22: *(undefined4 *)(param_1 + 7) = 1;
23: FUN_0011f0b0(param_1,1);
24: if (*(int *)((long)param_1 + 0x104) == 0) {
25: if (*(int *)((long)param_1 + 0x134) == 0) {
26: FUN_0011be10();
27: }
28: else {
29: FUN_001225a0();
30: }
31: }
32: else {
33: FUN_0014c870(param_1);
34: }
35: ppcVar2 = (code **)(**(code **)param_1[1])(param_1,1,0x78);
36: param_1[0x39] = (code *)ppcVar2;
37: ppcVar2[4] = param_2;
38: *ppcVar2 = FUN_00123f80;
39: ppcVar2[1] = FUN_00124030;
40: pcVar3 = (code *)(**(code **)(param_1[1] + 8))(param_1,1,0x500);
41: FUN_00148a80(pcVar3,0x500);
42: bVar6 = ((ulong)(ppcVar2 + 5) >> 3 & 1) == 0;
43: if (bVar6) {
44: iVar5 = 10;
45: }
46: else {
47: ppcVar2[5] = pcVar3;
48: iVar5 = 9;
49: }
50: uVar4 = (uint)!bVar6;
51: ppcVar1 = ppcVar2 + (ulong)((uint)((ulong)(ppcVar2 + 5) >> 3) & 1) + 5;
52: ppcVar1[2] = pcVar3 + (ulong)(uVar4 + 2) * 0x80;
53: ppcVar1[3] = pcVar3 + (ulong)(uVar4 + 3) * 0x80;
54: *ppcVar1 = pcVar3 + (ulong)uVar4 * 0x80;
55: ppcVar1[1] = pcVar3 + (ulong)(uVar4 + 1) * 0x80;
56: *(undefined (*) [16])(ppcVar1 + 6) =
57: CONCAT412((int)((ulong)(pcVar3 + (ulong)(uVar4 + 7) * 0x80) >> 0x20),
58: CONCAT48((int)(pcVar3 + (ulong)(uVar4 + 7) * 0x80),
59: pcVar3 + (ulong)(uVar4 + 6) * 0x80));
60: ppcVar1[4] = pcVar3 + (ulong)(uVar4 + 4) * 0x80;
61: ppcVar1[5] = pcVar3 + (ulong)(uVar4 + 5) * 0x80;
62: ppcVar2[(long)(int)(uVar4 + 8) + 5] = pcVar3 + (long)(int)(uVar4 + 8) * 0x80;
63: if (iVar5 != 9) {
64: ppcVar2[(long)(int)(uVar4 + 9) + 5] = pcVar3 + 0x480;
65: }
66: FUN_0011e1b0((int)(pcVar3 + (ulong)(uVar4 + 6) * 0x80),0,param_1);
67: (**(code **)(param_1[1] + 0x30))(param_1);
68: (**(code **)param_1[0x3a])(param_1);
69: *(undefined4 *)(param_1 + 0x26) = 0;
70: *(undefined4 *)((long)param_1 + 0x24) = 0x67;
71: return;
72: }
73: 
