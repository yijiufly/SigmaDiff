1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjDecompressToYUV2(long param_1,long param_2,long param_3,long param_4,int param_5,uint param_6,
6: int param_7,uint param_8)
7: 
8: {
9: int iVar1;
10: int iVar2;
11: int iVar3;
12: int iVar4;
13: undefined8 uVar5;
14: int *piVar6;
15: uint uStack88;
16: uint uStack84;
17: uint uStack80;
18: long lStack72;
19: long lStack64;
20: long lStack56;
21: 
22: if (param_1 == 0) {
23: ram0x003a6008 = ram0x003a6008 & 0xff00000000000000 | 0x656c646e6168;
24: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
25: return 0xffffffff;
26: }
27: *(undefined4 *)(param_1 + 0x5f8) = 0;
28: *(undefined4 *)(param_1 + 0x6d0) = 0;
29: *(uint *)(param_1 + 0x5fc) = param_8 >> 0xd & 1;
30: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 == 0)) ||
31: ((param_5 < 0 || ((int)param_6 < 1)))) || (((param_6 & param_6 - 1) != 0 || (param_7 < 0)))) {
32: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
33: ram0x003a6008 = 0x55596f5473736572;
34: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
35: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
36: *(undefined8 *)(param_1 + 0x618) = 0x6e49203a29283256;
37: *(undefined8 *)(param_1 + 0x620) = 0x72612064696c6176;
38: *(undefined4 *)(param_1 + 0x628) = 0x656d7567;
39: *(undefined2 *)(param_1 + 0x62c) = 0x746e;
40: *(undefined *)(param_1 + 0x62e) = 0;
41: *(undefined4 *)(param_1 + 0x6d0) = 1;
42: _DAT_003a6010 = 0x6e49203a29283256;
43: _DAT_003a6018 = 0x72612064696c6176;
44: _DAT_003a6020 = CONCAT17(DAT_003a6020_7,0x746e656d7567);
45: }
46: else {
47: iVar1 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
48: if (iVar1 != 0) {
49: return 0xffffffff;
50: }
51: FUN_00150390(param_1 + 0x208,param_2,param_3);
52: FUN_0011d3f0();
53: if (*(long *)(param_1 + 0x240) == 0x100000001) {
54: iVar1 = 3;
55: }
56: else {
57: iVar1 = FUN_00141f70();
58: if (iVar1 < 0) {
59: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
60: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
61: *(undefined8 *)(param_1 + 0x618) = 0x6f43203a29283256;
62: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20646c75;
63: *(undefined8 *)(param_1 + 0x628) = 0x6e696d7265746564;
64: *(undefined8 *)(param_1 + 0x630) = 0x6d61736275732065;
65: *(undefined8 *)(param_1 + 0x638) = 0x797420676e696c70;
66: *(undefined8 *)(param_1 + 0x640) = 0x4a20726f66206570;
67: *(undefined8 *)(param_1 + 0x648) = 0x67616d6920474550;
68: *(undefined2 *)(param_1 + 0x650) = 0x65;
69: *(undefined4 *)(param_1 + 0x6d0) = 1;
70: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
71: ram0x003a6008 = 0x55596f5473736572;
72: _DAT_003a6010 = 0x6f43203a29283256;
73: _DAT_003a6018 = 0x20746f6e20646c75;
74: _DAT_003a6020 = 0x6e696d7265746564;
75: _DAT_003a6028 = 0x6d61736275732065;
76: _DAT_003a6030 = 0x797420676e696c70;
77: _DAT_003a6038 = 0x4a20726f66206570;
78: _DAT_003a6040 = 0x67616d6920474550;
79: _DAT_003a6048 = 0x65;
80: goto LAB_0014987a;
81: }
82: }
83: piVar6 = (int *)&DAT_0018bb80;
84: if (param_5 == 0) {
85: param_5 = *(int *)(param_1 + 0x238);
86: }
87: iVar2 = *(int *)(param_1 + 0x23c);
88: if (param_7 != 0) {
89: iVar2 = param_7;
90: }
91: do {
92: iVar3 = piVar6[1];
93: if (((iVar3 + -1 + *(int *)(param_1 + 0x23c) * *piVar6) / iVar3 <= iVar2) &&
94: ((iVar3 + -1 + *piVar6 * *(int *)(param_1 + 0x238)) / iVar3 <= param_5)) {
95: iVar3 = tjPlaneWidth(0,param_5,iVar1);
96: iVar4 = tjPlaneHeight(0,iVar2,iVar1);
97: uStack88 = iVar3 + -1 + param_6 & -param_6;
98: lStack72 = param_4;
99: if (iVar1 == 3) {
100: uStack80 = 0;
101: lStack56 = 0;
102: lStack64 = 0;
103: }
104: else {
105: iVar3 = tjPlaneWidth(1,param_5,iVar1);
106: iVar1 = tjPlaneHeight(1,iVar2,iVar1);
107: uStack80 = iVar3 + -1 + param_6 & -param_6;
108: lStack64 = (int)(uStack88 * iVar4) + lStack72;
109: lStack56 = lStack64 + (int)(iVar1 * uStack80);
110: }
111: *(undefined4 *)(param_1 + 0x604) = 1;
112: uStack84 = uStack80;
113: uVar5 = tjDecompressToYUVPlanes
114: (param_1,param_2,param_3,&lStack72,param_5,&uStack88,iVar2,param_8);
115: return uVar5;
116: }
117: piVar6 = piVar6 + 2;
118: } while (piVar6 != (int *)&DAT_0018bc00);
119: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
120: *(undefined8 *)(param_1 + 0x610) = 0x55596f5473736572;
121: *(undefined8 *)(param_1 + 0x618) = 0x6f43203a29283256;
122: *(undefined8 *)(param_1 + 0x620) = 0x20746f6e20646c75;
123: *(undefined8 *)(param_1 + 0x628) = 0x6f6420656c616373;
124: *(undefined8 *)(param_1 + 0x630) = 0x6564206f74206e77;
125: *(undefined8 *)(param_1 + 0x638) = 0x6d69206465726973;
126: *(undefined8 *)(param_1 + 0x640) = 0x656d696420656761;
127: *(undefined4 *)(param_1 + 0x648) = 0x6f69736e;
128: *(undefined2 *)(param_1 + 0x64c) = 0x736e;
129: *(undefined *)(param_1 + 0x64e) = 0;
130: *(undefined4 *)(param_1 + 0x6d0) = 1;
131: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
132: ram0x003a6008 = 0x55596f5473736572;
133: _DAT_003a6010 = 0x6f43203a29283256;
134: _DAT_003a6018 = 0x20746f6e20646c75;
135: _DAT_003a6020 = 0x6f6420656c616373;
136: _DAT_003a6028 = 0x6564206f74206e77;
137: _DAT_003a6030 = 0x6d69206465726973;
138: _DAT_003a6038 = 0x656d696420656761;
139: _DAT_003a6040 = CONCAT17(DAT_003a6040_7,0x736e6f69736e);
140: }
141: LAB_0014987a:
142: *(undefined4 *)(param_1 + 0x5fc) = 0;
143: return 0xffffffff;
144: }
145: 
