1: 
2: void FUN_00102f10(code **param_1)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: code *pcVar3;
8: uint uVar4;
9: code *pcVar5;
10: 
11: iVar2 = *(int *)((long)param_1 + 0x24);
12: if (iVar2 - 0x65U < 2) {
13: if (*(uint *)((long)param_1 + 0x34) <= *(uint *)(param_1 + 0x26)) goto LAB_00102fc6;
14: ppcVar1 = (code **)*param_1;
15: *(undefined4 *)(ppcVar1 + 5) = 0x43;
16: (**ppcVar1)();
17: goto LAB_00102fc6;
18: }
19: if (iVar2 != 0x67) {
20: pcVar3 = *param_1;
21: *(int *)(pcVar3 + 0x2c) = iVar2;
22: ppcVar1 = (code **)*param_1;
23: *(undefined4 *)(pcVar3 + 0x28) = 0x14;
24: (**ppcVar1)();
25: }
26: ppcVar1 = (code **)param_1[0x36];
27: iVar2 = *(int *)((long)ppcVar1 + 0x1c);
28: do {
29: if (iVar2 != 0) {
30: (**(code **)(param_1[0x3a] + 0x18))(param_1);
31: (**(code **)(param_1[5] + 0x20))(param_1);
32: FUN_001166f0(param_1);
33: return;
34: }
35: pcVar5 = (code *)0x0;
36: (**ppcVar1)(param_1);
37: pcVar3 = (code *)(ulong)*(uint *)(param_1 + 0x28);
38: if (*(uint *)(param_1 + 0x28) != 0) {
39: do {
40: while( true ) {
41: ppcVar1 = (code **)param_1[2];
42: if (ppcVar1 != (code **)0x0) {
43: ppcVar1[1] = pcVar5;
44: ppcVar1[2] = pcVar3;
45: (**ppcVar1)(param_1);
46: }
47: iVar2 = (**(code **)(param_1[0x39] + 8))(param_1);
48: if (iVar2 != 0) break;
49: ppcVar1 = (code **)*param_1;
50: uVar4 = (int)pcVar5 + 1;
51: pcVar5 = (code *)(ulong)uVar4;
52: *(undefined4 *)(ppcVar1 + 5) = 0x18;
53: (**ppcVar1)(param_1);
54: pcVar3 = (code *)(ulong)*(uint *)(param_1 + 0x28);
55: if (*(uint *)(param_1 + 0x28) <= uVar4) goto LAB_00102fc6;
56: }
57: pcVar3 = (code *)(ulong)*(uint *)(param_1 + 0x28);
58: uVar4 = (int)pcVar5 + 1;
59: pcVar5 = (code *)(ulong)uVar4;
60: } while (uVar4 < *(uint *)(param_1 + 0x28));
61: }
62: LAB_00102fc6:
63: (**(code **)(param_1[0x36] + 0x10))(param_1);
64: ppcVar1 = (code **)param_1[0x36];
65: iVar2 = *(int *)((long)ppcVar1 + 0x1c);
66: } while( true );
67: }
68: 
