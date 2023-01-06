1: 
2: void FUN_001297f0(long *param_1,char *param_2,uint param_3,long param_4)
3: 
4: {
5: char cVar1;
6: byte bVar2;
7: long lVar3;
8: long lVar4;
9: ulong uVar5;
10: ulong uVar6;
11: undefined4 uVar7;
12: 
13: uVar7 = (undefined4)((ulong)param_3 + param_4);
14: if (param_3 < 0xe) {
15: if (((5 < param_3) && (*param_2 == 'J')) && (param_2[1] == 'F')) goto LAB_00129848;
16: LAB_0012980e:
17: lVar4 = *param_1;
18: *(undefined4 *)(lVar4 + 0x28) = 0x4d;
19: }
20: else {
21: if ((*param_2 != 'J') || (param_2[1] != 'F')) goto LAB_0012980e;
22: if ((param_2[2] == 'I') && ((param_2[3] == 'F' && (param_2[4] == '\0')))) {
23: *(undefined4 *)((long)param_1 + 0x174) = 1;
24: cVar1 = param_2[5];
25: *(char *)(param_1 + 0x2f) = cVar1;
26: *(char *)((long)param_1 + 0x179) = param_2[6];
27: *(char *)((long)param_1 + 0x17a) = param_2[7];
28: *(ushort *)((long)param_1 + 0x17c) =
29: (ushort)(byte)param_2[8] * 0x100 + (ushort)(byte)param_2[9];
30: *(ushort *)((long)param_1 + 0x17e) =
31: (ushort)(byte)param_2[10] * 0x100 + (ushort)(byte)param_2[0xb];
32: if (cVar1 != '\x01') {
33: lVar4 = *param_1;
34: *(undefined4 *)(lVar4 + 0x28) = 0x77;
35: *(uint *)(lVar4 + 0x2c) = (uint)*(byte *)(param_1 + 0x2f);
36: *(uint *)(*param_1 + 0x30) = (uint)*(byte *)((long)param_1 + 0x179);
37: (**(code **)(*param_1 + 8))(param_1,0xffffffff);
38: }
39: lVar4 = *param_1;
40: *(uint *)(lVar4 + 0x2c) = (uint)*(byte *)(param_1 + 0x2f);
41: *(uint *)(lVar4 + 0x30) = (uint)*(byte *)((long)param_1 + 0x179);
42: *(uint *)(lVar4 + 0x34) = (uint)*(ushort *)((long)param_1 + 0x17c);
43: *(uint *)(lVar4 + 0x38) = (uint)*(ushort *)((long)param_1 + 0x17e);
44: bVar2 = *(byte *)((long)param_1 + 0x17a);
45: *(undefined4 *)(lVar4 + 0x28) = 0x57;
46: *(uint *)(lVar4 + 0x3c) = (uint)bVar2;
47: (**(code **)(lVar4 + 8))(param_1);
48: uVar6 = 0;
49: uVar5 = 0;
50: if ((byte)(param_2[0xd] | param_2[0xc]) != 0) {
51: lVar4 = *param_1;
52: *(undefined4 *)(lVar4 + 0x28) = 0x5a;
53: *(uint *)(lVar4 + 0x2c) = (uint)(byte)param_2[0xc];
54: *(uint *)(*param_1 + 0x30) = (uint)(byte)param_2[0xd];
55: (**(code **)(*param_1 + 8))(param_1,1);
56: uVar5 = (ulong)(byte)param_2[0xc];
57: uVar6 = (ulong)(byte)param_2[0xd];
58: }
59: lVar4 = (ulong)param_3 + param_4 + -0xe;
60: if (uVar5 * uVar6 * 3 == lVar4) {
61: return;
62: }
63: lVar3 = *param_1;
64: *(undefined4 *)(lVar3 + 0x28) = 0x58;
65: *(int *)(lVar3 + 0x2c) = (int)lVar4;
66: goto LAB_0012981c;
67: }
68: LAB_00129848:
69: if ((param_2[2] != 'X') || ((param_2[3] != 'X' || (param_2[4] != '\0')))) goto LAB_0012980e;
70: cVar1 = param_2[5];
71: if (cVar1 == '\x11') {
72: lVar4 = *param_1;
73: *(undefined4 *)(lVar4 + 0x28) = 0x6d;
74: }
75: else {
76: if (cVar1 == '\x13') {
77: lVar4 = *param_1;
78: *(undefined4 *)(lVar4 + 0x28) = 0x6e;
79: }
80: else {
81: lVar4 = *param_1;
82: if (cVar1 != '\x10') {
83: *(undefined4 *)(lVar4 + 0x28) = 0x59;
84: *(uint *)(lVar4 + 0x2c) = (uint)(byte)param_2[5];
85: *(undefined4 *)(*param_1 + 0x30) = uVar7;
86: goto LAB_0012981c;
87: }
88: *(undefined4 *)(lVar4 + 0x28) = 0x6c;
89: }
90: }
91: }
92: *(undefined4 *)(lVar4 + 0x2c) = uVar7;
93: LAB_0012981c:
94: /* WARNING: Could not recover jumptable at 0x0012982f. Too many branches */
95: /* WARNING: Treating indirect jump as call */
96: (**(code **)(*param_1 + 8))(param_1,1);
97: return;
98: }
99: 
