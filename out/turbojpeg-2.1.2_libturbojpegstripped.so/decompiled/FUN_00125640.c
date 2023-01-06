1: 
2: undefined8 FUN_00125640(code **param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: uint uVar4;
9: undefined8 uVar5;
10: 
11: iVar1 = *(int *)((long)param_1 + 0x24);
12: if (iVar1 == 0xca) {
13: FUN_00137680();
14: if (*(int *)(param_1 + 0xb) != 0) {
15: *(undefined4 *)((long)param_1 + 0x24) = 0xcf;
16: return 1;
17: }
18: *(undefined4 *)((long)param_1 + 0x24) = 0xcb;
19: }
20: else {
21: if (iVar1 != 0xcb) {
22: if (iVar1 != 0xcc) {
23: ppcVar2 = (code **)*param_1;
24: *(undefined4 *)(ppcVar2 + 5) = 0x14;
25: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
26: (**ppcVar2)();
27: }
28: uVar5 = FUN_001254e0(param_1);
29: return uVar5;
30: }
31: }
32: if (*(int *)(param_1[0x48] + 0x20) != 0) {
33: ppcVar2 = (code **)param_1[2];
34: do {
35: if (ppcVar2 != (code **)0x0) {
36: (**ppcVar2)(param_1);
37: }
38: do {
39: uVar4 = (**(code **)param_1[0x48])(param_1);
40: if (uVar4 == 0) {
41: return 0;
42: }
43: if (uVar4 == 2) goto LAB_00125700;
44: ppcVar2 = (code **)param_1[2];
45: } while (ppcVar2 == (code **)0x0);
46: if ((uVar4 & 0xfffffffd) == 1) {
47: pcVar3 = ppcVar2[1];
48: ppcVar2[1] = pcVar3 + 1;
49: if ((long)ppcVar2[2] <= (long)(pcVar3 + 1)) {
50: ppcVar2[2] = ppcVar2[2] + *(uint *)((long)param_1 + 0x1a4);
51: }
52: }
53: } while( true );
54: }
55: LAB_00125700:
56: *(undefined4 *)((long)param_1 + 0xb4) = *(undefined4 *)((long)param_1 + 0xac);
57: uVar5 = FUN_001254e0(param_1);
58: return uVar5;
59: }
60: 
