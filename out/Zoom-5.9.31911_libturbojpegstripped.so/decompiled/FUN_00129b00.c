1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: undefined8 FUN_00129b00(long *param_1)
5: 
6: {
7: byte bVar1;
8: byte **ppbVar2;
9: long lVar3;
10: int iVar4;
11: byte *pbVar5;
12: byte *pbVar6;
13: 
14: ppbVar2 = (byte **)param_1[5];
15: pbVar6 = ppbVar2[1];
16: pbVar5 = *ppbVar2;
17: if (pbVar6 == (byte *)0x0) goto LAB_00129bd1;
18: do {
19: bVar1 = *pbVar5;
20: while( true ) {
21: while( true ) {
22: pbVar5 = pbVar5 + 1;
23: pbVar6 = pbVar6 + -1;
24: if (bVar1 == 0xff) break;
25: *(int *)(param_1[0x49] + 0x24) = *(int *)(param_1[0x49] + 0x24) + 1;
26: *ppbVar2 = pbVar5;
27: ppbVar2[1] = pbVar6;
28: if (pbVar6 == (byte *)0x0) {
29: iVar4 = (*(code *)ppbVar2[3])(param_1);
30: if (iVar4 == 0) {
31: return 0;
32: }
33: pbVar5 = *ppbVar2;
34: pbVar6 = ppbVar2[1];
35: }
36: bVar1 = *pbVar5;
37: }
38: do {
39: if (pbVar6 == (byte *)0x0) {
40: iVar4 = (*(code *)ppbVar2[3])(param_1);
41: if (iVar4 == 0) {
42: return 0;
43: }
44: pbVar5 = *ppbVar2;
45: pbVar6 = ppbVar2[1];
46: }
47: bVar1 = *pbVar5;
48: pbVar6 = pbVar6 + -1;
49: pbVar5 = pbVar5 + 1;
50: } while (bVar1 == 0xff);
51: if (bVar1 != 0) {
52: if (*(int *)(param_1[0x49] + 0x24) != 0) {
53: lVar3 = *param_1;
54: *(undefined4 *)(lVar3 + 0x2c) = *(undefined4 *)(param_1[0x49] + 0x24);
55: *(undefined4 *)(lVar3 + 0x28) = 0x74;
56: *(uint *)(*param_1 + 0x30) = (uint)bVar1;
57: (**(code **)(*param_1 + 8))(param_1,0xffffffff);
58: *(undefined4 *)(param_1[0x49] + 0x24) = 0;
59: }
60: *(uint *)((long)param_1 + 0x21c) = (uint)bVar1;
61: *ppbVar2 = pbVar5;
62: ppbVar2[1] = pbVar6;
63: return 1;
64: }
65: *(int *)(param_1[0x49] + 0x24) = *(int *)(param_1[0x49] + 0x24) + 2;
66: *ppbVar2 = pbVar5;
67: ppbVar2[1] = pbVar6;
68: if (pbVar6 != (byte *)0x0) break;
69: LAB_00129bd1:
70: iVar4 = (*(code *)ppbVar2[3])(param_1);
71: if (iVar4 == 0) {
72: return 0;
73: }
74: pbVar5 = *ppbVar2;
75: pbVar6 = ppbVar2[1];
76: bVar1 = *pbVar5;
77: }
78: } while( true );
79: }
80: 
