1: 
2: undefined8 FUN_00125d30(byte **param_1,byte *param_2,int param_3,int param_4)
3: 
4: {
5: byte bVar1;
6: long *plVar2;
7: long lVar3;
8: char cVar4;
9: int iVar5;
10: byte *pbVar6;
11: byte *pbVar7;
12: ulong uVar8;
13: byte *pbVar9;
14: 
15: plVar2 = (long *)param_1[4];
16: pbVar9 = *param_1;
17: pbVar7 = param_1[1];
18: if (*(int *)((long)plVar2 + 0x21c) == 0) {
19: if (param_3 < 0x39) {
20: do {
21: if (pbVar7 == (byte *)0x0) {
22: iVar5 = (**(code **)(plVar2[5] + 0x18))(plVar2);
23: if (iVar5 == 0) {
24: return 0;
25: }
26: pbVar9 = *(byte **)plVar2[5];
27: pbVar7 = ((byte **)plVar2[5])[1];
28: }
29: bVar1 = *pbVar9;
30: pbVar9 = pbVar9 + 1;
31: pbVar7 = pbVar7 + -1;
32: uVar8 = (ulong)bVar1;
33: pbVar6 = pbVar9;
34: if (bVar1 == 0xff) {
35: do {
36: if (pbVar7 == (byte *)0x0) {
37: iVar5 = (**(code **)(plVar2[5] + 0x18))(plVar2);
38: if (iVar5 == 0) {
39: return 0;
40: }
41: pbVar6 = *(byte **)plVar2[5];
42: pbVar7 = ((byte **)plVar2[5])[1];
43: }
44: pbVar9 = pbVar6 + 1;
45: bVar1 = *pbVar6;
46: pbVar7 = pbVar7 + -1;
47: pbVar6 = pbVar9;
48: } while (bVar1 == 0xff);
49: if (bVar1 != 0) {
50: *(uint *)((long)plVar2 + 0x21c) = (uint)bVar1;
51: goto LAB_00125e30;
52: }
53: uVar8 = 0xff;
54: }
55: param_3 = param_3 + 8;
56: param_2 = (byte *)((long)param_2 << 8 | uVar8);
57: } while (param_3 < 0x39);
58: }
59: }
60: else {
61: LAB_00125e30:
62: if (param_3 < param_4) {
63: if (*(int *)(plVar2[0x4a] + 0x10) == 0) {
64: lVar3 = *plVar2;
65: *(undefined4 *)(lVar3 + 0x28) = 0x75;
66: (**(code **)(lVar3 + 8))(plVar2,0xffffffff);
67: *(undefined4 *)(plVar2[0x4a] + 0x10) = 1;
68: }
69: cVar4 = (char)param_3;
70: param_3 = 0x39;
71: param_2 = (byte *)((long)param_2 << (0x39U - cVar4 & 0x3f));
72: }
73: }
74: param_1[1] = pbVar7;
75: param_1[2] = param_2;
76: *(int *)(param_1 + 3) = param_3;
77: *param_1 = pbVar9;
78: return 1;
79: }
80: 
