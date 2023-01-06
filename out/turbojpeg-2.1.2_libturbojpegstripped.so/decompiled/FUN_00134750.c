1: 
2: void FUN_00134750(long *param_1,char *param_2,uint param_3,long param_4)
3: 
4: {
5: char cVar1;
6: byte bVar2;
7: byte bVar3;
8: code *UNRECOVERED_JUMPTABLE;
9: long lVar4;
10: undefined4 uVar5;
11: long lVar6;
12: 
13: lVar6 = *param_1;
14: UNRECOVERED_JUMPTABLE = *(code **)(lVar6 + 8);
15: uVar5 = (undefined4)(param_4 + (ulong)param_3);
16: if (param_3 < 0xe) {
17: if (((param_3 < 6) || (*param_2 != 'J')) || (param_2[1] != 'F')) goto LAB_00134769;
18: }
19: else {
20: if ((*param_2 != 'J') || (param_2[1] != 'F')) goto LAB_00134769;
21: if ((param_2[2] == 'I') && ((param_2[3] == 'F' && (param_2[4] == '\0')))) {
22: *(undefined4 *)((long)param_1 + 0x174) = 1;
23: bVar2 = param_2[5];
24: *(byte *)(param_1 + 0x2f) = bVar2;
25: bVar3 = param_2[6];
26: *(byte *)((long)param_1 + 0x179) = bVar3;
27: *(char *)((long)param_1 + 0x17a) = param_2[7];
28: *(ushort *)((long)param_1 + 0x17c) =
29: (ushort)(byte)param_2[8] * 0x100 + (ushort)(byte)param_2[9];
30: *(ushort *)((long)param_1 + 0x17e) =
31: (ushort)(byte)param_2[10] * 0x100 + (ushort)(byte)param_2[0xb];
32: if (bVar2 != 1) {
33: *(uint *)(lVar6 + 0x30) = (uint)bVar3;
34: *(undefined4 *)(lVar6 + 0x28) = 0x77;
35: *(uint *)(lVar6 + 0x2c) = (uint)bVar2;
36: (*UNRECOVERED_JUMPTABLE)(param_1,0xffffffff);
37: lVar6 = *param_1;
38: }
39: *(uint *)(lVar6 + 0x2c) = (uint)*(byte *)(param_1 + 0x2f);
40: *(uint *)(lVar6 + 0x30) = (uint)*(byte *)((long)param_1 + 0x179);
41: *(uint *)(lVar6 + 0x34) = (uint)*(ushort *)((long)param_1 + 0x17c);
42: *(uint *)(lVar6 + 0x38) = (uint)*(ushort *)((long)param_1 + 0x17e);
43: bVar2 = *(byte *)((long)param_1 + 0x17a);
44: *(undefined4 *)(lVar6 + 0x28) = 0x57;
45: *(uint *)(lVar6 + 0x3c) = (uint)bVar2;
46: (**(code **)(lVar6 + 8))(param_1,1);
47: if ((byte)(param_2[0xc] | param_2[0xd]) != 0) {
48: lVar6 = *param_1;
49: *(undefined4 *)(lVar6 + 0x28) = 0x5a;
50: *(uint *)(lVar6 + 0x2c) = (uint)(byte)param_2[0xc];
51: *(uint *)(lVar6 + 0x30) = (uint)(byte)param_2[0xd];
52: (**(code **)(lVar6 + 8))(param_1,1);
53: }
54: lVar6 = param_4 + (ulong)param_3 + -0xe;
55: if ((ulong)(byte)param_2[0xc] * (ulong)(byte)param_2[0xd] * 3 == lVar6) {
56: return;
57: }
58: lVar4 = *param_1;
59: *(undefined4 *)(lVar4 + 0x28) = 0x58;
60: *(int *)(lVar4 + 0x2c) = (int)lVar6;
61: /* WARNING: Could not recover jumptable at 0x00134947. Too many branches */
62: /* WARNING: Treating indirect jump as call */
63: (**(code **)(lVar4 + 8))(param_1,1);
64: return;
65: }
66: }
67: if (((param_2[2] == 'X') && (param_2[3] == 'X')) && (param_2[4] == '\0')) {
68: cVar1 = param_2[5];
69: if (cVar1 == '\x11') {
70: *(undefined4 *)(lVar6 + 0x28) = 0x6d;
71: *(undefined4 *)(lVar6 + 0x2c) = uVar5;
72: /* WARNING: Could not recover jumptable at 0x00134986. Too many branches */
73: /* WARNING: Treating indirect jump as call */
74: (*UNRECOVERED_JUMPTABLE)(param_1,1);
75: return;
76: }
77: if (cVar1 == '\x13') {
78: *(undefined4 *)(lVar6 + 0x28) = 0x6e;
79: *(undefined4 *)(lVar6 + 0x2c) = uVar5;
80: /* WARNING: Could not recover jumptable at 0x00134973. Too many branches */
81: /* WARNING: Treating indirect jump as call */
82: (*UNRECOVERED_JUMPTABLE)(param_1,1);
83: return;
84: }
85: if (cVar1 == '\x10') {
86: *(undefined4 *)(lVar6 + 0x28) = 0x6c;
87: *(undefined4 *)(lVar6 + 0x2c) = uVar5;
88: /* WARNING: Could not recover jumptable at 0x00134960. Too many branches */
89: /* WARNING: Treating indirect jump as call */
90: (*UNRECOVERED_JUMPTABLE)(param_1,1);
91: return;
92: }
93: *(undefined4 *)(lVar6 + 0x28) = 0x59;
94: bVar2 = param_2[5];
95: *(undefined4 *)(lVar6 + 0x30) = uVar5;
96: *(uint *)(lVar6 + 0x2c) = (uint)bVar2;
97: /* WARNING: Could not recover jumptable at 0x001347ef. Too many branches */
98: /* WARNING: Treating indirect jump as call */
99: (*UNRECOVERED_JUMPTABLE)(param_1,1);
100: return;
101: }
102: LAB_00134769:
103: *(undefined4 *)(lVar6 + 0x28) = 0x4d;
104: *(undefined4 *)(lVar6 + 0x2c) = uVar5;
105: /* WARNING: Could not recover jumptable at 0x00134779. Too many branches */
106: /* WARNING: Treating indirect jump as call */
107: (*UNRECOVERED_JUMPTABLE)(param_1,1);
108: return;
109: }
110: 
