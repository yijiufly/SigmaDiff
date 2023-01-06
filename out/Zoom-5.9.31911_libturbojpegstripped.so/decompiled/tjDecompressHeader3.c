1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined4
5: tjDecompressHeader3(long param_1,long param_2,long param_3,int *param_4,int *param_5,int *param_6,
6: int *param_7)
7: 
8: {
9: long lVar1;
10: undefined4 uVar2;
11: int iVar3;
12: undefined4 uVar4;
13: 
14: if (param_1 == 0) {
15: s_No_error_003a6000._0_8_ = 0x2064696c61766e49;
16: uVar2 = 0xffffffff;
17: ram0x003a6008 = ram0x003a6008 & 0xff00000000000000 | 0x656c646e6168;
18: }
19: else {
20: *(undefined4 *)(param_1 + 0x5f8) = 0;
21: *(undefined4 *)(param_1 + 0x6d0) = 0;
22: if ((*(byte *)(param_1 + 0x600) & 2) == 0) {
23: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
24: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
25: *(undefined8 *)(param_1 + 0x618) = 0x49203a2928337265;
26: *(undefined8 *)(param_1 + 0x620) = 0x2065636e6174736e;
27: *(undefined8 *)(param_1 + 0x628) = 0x20746f6e20736168;
28: *(undefined8 *)(param_1 + 0x648) = 0x6973736572706d6f;
29: *(undefined8 *)(param_1 + 0x630) = 0x696e69206e656562;
30: *(undefined8 *)(param_1 + 0x638) = 0x64657a696c616974;
31: *(undefined8 *)(param_1 + 0x640) = 0x63656420726f6620;
32: *(undefined2 *)(param_1 + 0x650) = 0x6e6f;
33: *(undefined *)(param_1 + 0x652) = 0;
34: *(undefined4 *)(param_1 + 0x6d0) = 1;
35: _DAT_003a6040 = 0x6973736572706d6f;
36: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
37: uVar4 = 0xffffffff;
38: ram0x003a6008 = 0x6461654873736572;
39: _DAT_003a6010 = 0x49203a2928337265;
40: _DAT_003a6018 = 0x2065636e6174736e;
41: _DAT_003a6020 = 0x20746f6e20736168;
42: _DAT_003a6028 = 0x696e69206e656562;
43: _DAT_003a6030 = 0x64657a696c616974;
44: _DAT_003a6038 = 0x63656420726f6620;
45: _DAT_003a6048 = 0x6e6f;
46: DAT_003a604a = 0;
47: }
48: else {
49: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 == (int *)0x0)) ||
50: ((param_5 == (int *)0x0 || (param_6 == (int *)0x0)))) || (param_7 == (int *)0x0)) {
51: _DAT_003a6020 = 0x746e656d756772;
52: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
53: *(undefined8 *)(param_1 + 0x628) = 0x746e656d756772;
54: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
55: uVar4 = 0xffffffff;
56: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
57: *(undefined8 *)(param_1 + 0x618) = 0x49203a2928337265;
58: *(undefined8 *)(param_1 + 0x620) = 0x612064696c61766e;
59: *(undefined4 *)(param_1 + 0x6d0) = 1;
60: ram0x003a6008 = 0x6461654873736572;
61: _DAT_003a6010 = 0x49203a2928337265;
62: _DAT_003a6018 = 0x612064696c61766e;
63: }
64: else {
65: iVar3 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
66: if (iVar3 != 0) {
67: return 0xffffffff;
68: }
69: lVar1 = param_1 + 0x208;
70: FUN_00150390(lVar1,param_2,param_3);
71: FUN_0011d3f0(lVar1,1);
72: *param_4 = *(int *)(param_1 + 0x238);
73: *param_5 = *(int *)(param_1 + 0x23c);
74: iVar3 = 3;
75: if (*(long *)(param_1 + 0x240) != 0x100000001) {
76: iVar3 = FUN_00141f70(lVar1);
77: }
78: *param_6 = iVar3;
79: switch(*(undefined4 *)(param_1 + 0x244)) {
80: default:
81: *param_7 = -1;
82: break;
83: case 1:
84: *param_7 = 2;
85: break;
86: case 2:
87: *param_7 = 0;
88: break;
89: case 3:
90: *param_7 = 1;
91: break;
92: case 4:
93: *param_7 = 3;
94: break;
95: case 5:
96: *param_7 = 4;
97: }
98: thunk_FUN_001166f0(lVar1);
99: if (*param_6 < 0) {
100: *(undefined8 *)(param_1 + 0x648) = 0x616d69204745504a;
101: _DAT_003a6040 = 0x616d69204745504a;
102: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
103: uVar4 = 0xffffffff;
104: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
105: *(undefined8 *)(param_1 + 0x618) = 0x43203a2928337265;
106: *(undefined8 *)(param_1 + 0x620) = 0x746f6e20646c756f;
107: *(undefined8 *)(param_1 + 0x628) = 0x696d726574656420;
108: *(undefined8 *)(param_1 + 0x630) = 0x617362757320656e;
109: *(undefined8 *)(param_1 + 0x638) = 0x7420676e696c706d;
110: *(undefined8 *)(param_1 + 0x640) = 0x20726f6620657079;
111: *(undefined2 *)(param_1 + 0x650) = 0x6567;
112: *(undefined *)(param_1 + 0x652) = 0;
113: *(undefined4 *)(param_1 + 0x6d0) = 1;
114: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
115: ram0x003a6008 = 0x6461654873736572;
116: _DAT_003a6010 = 0x43203a2928337265;
117: _DAT_003a6018 = 0x746f6e20646c756f;
118: _DAT_003a6020 = 0x696d726574656420;
119: _DAT_003a6028 = 0x617362757320656e;
120: _DAT_003a6030 = 0x7420676e696c706d;
121: _DAT_003a6038 = 0x20726f6620657079;
122: _DAT_003a6048 = 0x6567;
123: DAT_003a604a = 0;
124: }
125: else {
126: if (*param_7 < 0) {
127: *(undefined8 *)(param_1 + 0x640) = 0x6d69204745504a20;
128: _DAT_003a6038 = 0x6d69204745504a20;
129: uVar4 = 0xffffffff;
130: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
131: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
132: *(undefined8 *)(param_1 + 0x618) = 0x43203a2928337265;
133: *(undefined8 *)(param_1 + 0x620) = 0x746f6e20646c756f;
134: *(undefined8 *)(param_1 + 0x628) = 0x696d726574656420;
135: *(undefined8 *)(param_1 + 0x630) = 0x726f6c6f6320656e;
136: *(undefined8 *)(param_1 + 0x638) = 0x666f206563617073;
137: *(undefined4 *)(param_1 + 0x648) = 0x656761;
138: *(undefined4 *)(param_1 + 0x6d0) = 1;
139: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
140: ram0x003a6008 = 0x6461654873736572;
141: _DAT_003a6010 = 0x43203a2928337265;
142: _DAT_003a6018 = 0x746f6e20646c756f;
143: _DAT_003a6020 = 0x696d726574656420;
144: _DAT_003a6028 = 0x726f6c6f6320656e;
145: _DAT_003a6030 = 0x666f206563617073;
146: _DAT_003a6040 = CONCAT44(_DAT_003a6044,0x656761);
147: }
148: else {
149: if ((*param_4 < 1) || (uVar4 = 0, *param_5 < 1)) {
150: *(undefined8 *)(param_1 + 0x630) = 0x206e692064656e72;
151: _DAT_003a6028 = 0x206e692064656e72;
152: uVar4 = 0xffffffff;
153: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
154: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
155: *(undefined8 *)(param_1 + 0x618) = 0x49203a2928337265;
156: *(undefined8 *)(param_1 + 0x620) = 0x642064696c61766e;
157: *(undefined8 *)(param_1 + 0x628) = 0x7574657220617461;
158: *(undefined4 *)(param_1 + 0x638) = 0x64616568;
159: *(undefined2 *)(param_1 + 0x63c) = 0x7265;
160: *(undefined *)(param_1 + 0x63e) = 0;
161: *(undefined4 *)(param_1 + 0x6d0) = 1;
162: s_No_error_003a6000._0_8_ = 0x706d6f6365446a74;
163: ram0x003a6008 = 0x6461654873736572;
164: _DAT_003a6010 = 0x49203a2928337265;
165: _DAT_003a6018 = 0x642064696c61766e;
166: _DAT_003a6020 = 0x7574657220617461;
167: _DAT_003a6030 = CONCAT17(DAT_003a6030_7,0x726564616568);
168: }
169: }
170: }
171: }
172: }
173: uVar2 = 0xffffffff;
174: if (*(int *)(param_1 + 0x5f8) == 0) {
175: uVar2 = uVar4;
176: }
177: }
178: return uVar2;
179: }
180: 
