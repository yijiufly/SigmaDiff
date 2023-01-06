1: 
2: undefined8 FUN_00130960(byte **param_1,byte *param_2,int param_3,int param_4)
3: 
4: {
5: byte bVar1;
6: long *plVar2;
7: long lVar3;
8: int iVar4;
9: char cVar5;
10: uint uVar6;
11: int iVar7;
12: byte *pbVar8;
13: byte *pbVar9;
14: ulong uVar10;
15: byte *pbVar11;
16: 
17: plVar2 = (long *)param_1[4];
18: pbVar8 = *param_1;
19: pbVar11 = param_1[1];
20: if (*(int *)((long)plVar2 + 0x21c) == 0) {
21: if (param_3 < 0x39) {
22: uVar6 = 0x38 - param_3;
23: iVar4 = param_3 + 8;
24: do {
25: if (pbVar11 == (byte *)0x0) {
26: iVar7 = (**(code **)(plVar2[5] + 0x18))(plVar2);
27: if (iVar7 == 0) {
28: return 0;
29: }
30: pbVar8 = *(byte **)plVar2[5];
31: pbVar11 = ((byte **)plVar2[5])[1];
32: }
33: bVar1 = *pbVar8;
34: uVar10 = (ulong)bVar1;
35: pbVar11 = pbVar11 + -1;
36: pbVar8 = pbVar8 + 1;
37: pbVar9 = pbVar8;
38: if (bVar1 == 0xff) {
39: do {
40: if (pbVar11 == (byte *)0x0) {
41: iVar7 = (**(code **)(plVar2[5] + 0x18))(plVar2);
42: if (iVar7 == 0) {
43: return 0;
44: }
45: pbVar9 = *(byte **)plVar2[5];
46: pbVar11 = ((byte **)plVar2[5])[1];
47: }
48: pbVar8 = pbVar9 + 1;
49: bVar1 = *pbVar9;
50: pbVar11 = pbVar11 + -1;
51: pbVar9 = pbVar8;
52: } while (bVar1 == 0xff);
53: if (bVar1 != 0) {
54: *(uint *)((long)plVar2 + 0x21c) = (uint)bVar1;
55: goto LAB_00130a58;
56: }
57: uVar10 = 0xff;
58: }
59: param_3 = param_3 + 8;
60: param_2 = (byte *)((long)param_2 << 8 | uVar10);
61: } while (iVar4 + (uVar6 & 0xfffffff8) != param_3);
62: }
63: }
64: else {
65: LAB_00130a58:
66: if (param_3 < param_4) {
67: if (*(int *)(plVar2[0x4a] + 0x10) == 0) {
68: lVar3 = *plVar2;
69: *(undefined4 *)(lVar3 + 0x28) = 0x75;
70: (**(code **)(lVar3 + 8))(plVar2,0xffffffff);
71: *(undefined4 *)(plVar2[0x4a] + 0x10) = 1;
72: }
73: cVar5 = (char)param_3;
74: param_3 = 0x39;
75: param_2 = (byte *)((long)param_2 << (0x39U - cVar5 & 0x3f));
76: }
77: }
78: param_1[1] = pbVar11;
79: param_1[2] = param_2;
80: *(int *)(param_1 + 3) = param_3;
81: *param_1 = pbVar8;
82: return 1;
83: }
84: 
