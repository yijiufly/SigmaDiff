1: 
2: void FUN_00102d50(code **param_1)
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
13: if (*(uint *)((long)param_1 + 0x34) <= *(uint *)(param_1 + 0x26)) goto LAB_00102df1;
14: ppcVar1 = (code **)*param_1;
15: *(undefined4 *)(ppcVar1 + 5) = 0x43;
16: (**ppcVar1)();
17: (**(code **)(param_1[0x36] + 0x10))(param_1);
18: goto LAB_00102dfe;
19: }
20: if (iVar2 != 0x67) {
21: ppcVar1 = (code **)*param_1;
22: *(undefined4 *)(ppcVar1 + 5) = 0x14;
23: *(int *)((long)ppcVar1 + 0x2c) = iVar2;
24: (**ppcVar1)();
25: }
26: ppcVar1 = (code **)param_1[0x36];
27: iVar2 = *(int *)((long)ppcVar1 + 0x1c);
28: do {
29: if (iVar2 != 0) {
30: (**(code **)(param_1[0x3a] + 0x18))(param_1);
31: (**(code **)(param_1[5] + 0x20))(param_1);
32: FUN_0011f490(param_1);
33: return;
34: }
35: pcVar5 = (code *)0x0;
36: (**ppcVar1)(param_1);
37: pcVar3 = (code *)(ulong)*(uint *)(param_1 + 0x28);
38: if (*(uint *)(param_1 + 0x28) == 0) {
39: LAB_00102df1:
40: (**(code **)(param_1[0x36] + 0x10))(param_1);
41: }
42: else {
43: do {
44: while( true ) {
45: ppcVar1 = (code **)param_1[2];
46: if (ppcVar1 != (code **)0x0) {
47: ppcVar1[1] = pcVar5;
48: ppcVar1[2] = pcVar3;
49: (**ppcVar1)(param_1);
50: }
51: iVar2 = (**(code **)(param_1[0x39] + 8))(param_1);
52: if (iVar2 != 0) break;
53: ppcVar1 = (code **)*param_1;
54: uVar4 = (int)pcVar5 + 1;
55: pcVar5 = (code *)(ulong)uVar4;
56: *(undefined4 *)(ppcVar1 + 5) = 0x18;
57: (**ppcVar1)(param_1);
58: pcVar3 = (code *)(ulong)*(uint *)(param_1 + 0x28);
59: if (*(uint *)(param_1 + 0x28) <= uVar4) goto LAB_00102df1;
60: }
61: pcVar3 = (code *)(ulong)*(uint *)(param_1 + 0x28);
62: uVar4 = (int)pcVar5 + 1;
63: pcVar5 = (code *)(ulong)uVar4;
64: } while (uVar4 < *(uint *)(param_1 + 0x28));
65: (**(code **)(param_1[0x36] + 0x10))(param_1);
66: }
67: LAB_00102dfe:
68: ppcVar1 = (code **)param_1[0x36];
69: iVar2 = *(int *)((long)ppcVar1 + 0x1c);
70: } while( true );
71: }
72: 
