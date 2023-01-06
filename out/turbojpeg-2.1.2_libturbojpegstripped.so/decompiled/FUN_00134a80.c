1: 
2: undefined8 FUN_00134a80(long *param_1)
3: 
4: {
5: byte bVar1;
6: byte **ppbVar2;
7: long lVar3;
8: int iVar4;
9: byte *pbVar5;
10: byte *pbVar6;
11: 
12: ppbVar2 = (byte **)param_1[5];
13: pbVar5 = *ppbVar2;
14: pbVar6 = ppbVar2[1];
15: while( true ) {
16: while( true ) {
17: if (pbVar6 == (byte *)0x0) {
18: iVar4 = (*(code *)ppbVar2[3])(param_1);
19: if (iVar4 == 0) {
20: return 0;
21: }
22: pbVar5 = *ppbVar2;
23: pbVar6 = ppbVar2[1];
24: }
25: pbVar6 = pbVar6 + -1;
26: bVar1 = *pbVar5;
27: pbVar5 = pbVar5 + 1;
28: if (bVar1 == 0xff) break;
29: *(int *)(param_1[0x49] + 0x24) = *(int *)(param_1[0x49] + 0x24) + 1;
30: *ppbVar2 = pbVar5;
31: ppbVar2[1] = pbVar6;
32: }
33: do {
34: if (pbVar6 == (byte *)0x0) {
35: iVar4 = (*(code *)ppbVar2[3])(param_1);
36: if (iVar4 == 0) {
37: return 0;
38: }
39: pbVar5 = *ppbVar2;
40: pbVar6 = ppbVar2[1];
41: }
42: bVar1 = *pbVar5;
43: pbVar6 = pbVar6 + -1;
44: pbVar5 = pbVar5 + 1;
45: } while (bVar1 == 0xff);
46: iVar4 = *(int *)(param_1[0x49] + 0x24);
47: if (bVar1 != 0) break;
48: *(int *)(param_1[0x49] + 0x24) = iVar4 + 2;
49: *ppbVar2 = pbVar5;
50: ppbVar2[1] = pbVar6;
51: }
52: if (iVar4 != 0) {
53: lVar3 = *param_1;
54: *(int *)(lVar3 + 0x2c) = iVar4;
55: *(undefined4 *)(lVar3 + 0x28) = 0x74;
56: *(uint *)(lVar3 + 0x30) = (uint)bVar1;
57: (**(code **)(lVar3 + 8))(param_1,0xffffffff);
58: *(undefined4 *)(param_1[0x49] + 0x24) = 0;
59: }
60: *(uint *)((long)param_1 + 0x21c) = (uint)bVar1;
61: *ppbVar2 = pbVar5;
62: ppbVar2[1] = pbVar6;
63: return 1;
64: }
65: 
