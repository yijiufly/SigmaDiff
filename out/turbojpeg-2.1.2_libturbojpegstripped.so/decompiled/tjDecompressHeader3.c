1: 
2: int tjDecompressHeader3(long param_1,long param_2,long param_3,int *param_4,int *param_5,
3: int *param_6,int *param_7)
4: 
5: {
6: long lVar1;
7: int iVar2;
8: int iVar3;
9: undefined4 *puVar4;
10: undefined8 *puVar5;
11: 
12: if (param_1 == 0) {
13: puVar5 = (undefined8 *)__tls_get_addr(&PTR_00398fc0);
14: *puVar5 = 0x2064696c61766e49;
15: *(undefined4 *)(puVar5 + 1) = 0x646e6168;
16: *(undefined2 *)((long)puVar5 + 0xc) = 0x656c;
17: *(undefined *)((long)puVar5 + 0xe) = 0;
18: }
19: else {
20: *(undefined4 *)(param_1 + 0x5f8) = 0;
21: *(undefined4 *)(param_1 + 0x6d0) = 0;
22: if ((*(byte *)(param_1 + 0x600) & 2) == 0) {
23: *(undefined8 *)(param_1 + 0x648) = 0x6973736572706d6f;
24: *(undefined *)(param_1 + 0x652) = 0;
25: *(undefined2 *)(param_1 + 0x650) = 0x6e6f;
26: *(undefined4 *)(param_1 + 0x6d0) = 1;
27: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
28: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
29: *(undefined8 *)(param_1 + 0x618) = 0x49203a2928337265;
30: *(undefined8 *)(param_1 + 0x620) = 0x2065636e6174736e;
31: *(undefined8 *)(param_1 + 0x628) = 0x20746f6e20736168;
32: *(undefined8 *)(param_1 + 0x630) = 0x696e69206e656562;
33: *(undefined8 *)(param_1 + 0x638) = 0x64657a696c616974;
34: *(undefined8 *)(param_1 + 0x640) = 0x63656420726f6620;
35: puVar4 = (undefined4 *)
36: __tls_get_addr(0x64657a696c616974,0x20746f6e20736168,0x49203a2928337265,
37: 0x706d6f6365446a74,&PTR_00398fc0);
38: *(undefined8 *)(puVar4 + 0x10) = 0x6973736572706d6f;
39: *(undefined *)((long)puVar4 + 0x4a) = 0;
40: *(undefined2 *)(puVar4 + 0x12) = 0x6e6f;
41: *puVar4 = 0x65446a74;
42: puVar4[1] = 0x706d6f63;
43: puVar4[2] = 0x73736572;
44: puVar4[3] = 0x64616548;
45: puVar4[4] = 0x28337265;
46: puVar4[5] = 0x49203a29;
47: puVar4[6] = 0x6174736e;
48: puVar4[7] = 0x2065636e;
49: puVar4[8] = 0x20736168;
50: puVar4[9] = 0x20746f6e;
51: puVar4[10] = 0x6e656562;
52: puVar4[0xb] = 0x696e6920;
53: puVar4[0xc] = 0x6c616974;
54: puVar4[0xd] = 0x64657a69;
55: puVar4[0xe] = 0x726f6620;
56: puVar4[0xf] = 0x63656420;
57: return -1;
58: }
59: if (((((param_2 == 0) || (param_3 == 0)) || (param_4 == (int *)0x0)) ||
60: ((param_5 == (int *)0x0 || (param_6 == (int *)0x0)))) || (param_7 == (int *)0x0)) {
61: *(undefined8 *)(param_1 + 0x628) = 0x746e656d756772;
62: *(undefined4 *)(param_1 + 0x6d0) = 1;
63: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
64: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
65: *(undefined8 *)(param_1 + 0x618) = 0x49203a2928337265;
66: *(undefined8 *)(param_1 + 0x620) = 0x612064696c61766e;
67: puVar4 = (undefined4 *)__tls_get_addr(0x49203a2928337265,0x706d6f6365446a74,&PTR_00398fc0);
68: *(undefined8 *)(puVar4 + 8) = 0x746e656d756772;
69: *puVar4 = 0x65446a74;
70: puVar4[1] = 0x706d6f63;
71: puVar4[2] = 0x73736572;
72: puVar4[3] = 0x64616548;
73: puVar4[4] = 0x28337265;
74: puVar4[5] = 0x49203a29;
75: puVar4[6] = 0x6c61766e;
76: puVar4[7] = 0x61206469;
77: }
78: else {
79: iVar2 = _setjmp((__jmp_buf_tag *)(param_1 + 0x528));
80: if (iVar2 == 0) {
81: lVar1 = param_1 + 0x208;
82: FUN_00167270(lVar1,param_2,param_3);
83: FUN_00125330(lVar1);
84: *param_4 = *(int *)(param_1 + 0x238);
85: *param_5 = *(int *)(param_1 + 0x23c);
86: iVar3 = 3;
87: if (*(long *)(param_1 + 0x240) != 0x100000001) {
88: iVar3 = FUN_0014e860(lVar1);
89: }
90: *param_6 = iVar3;
91: switch(*(undefined4 *)(param_1 + 0x244)) {
92: default:
93: *param_7 = -1;
94: break;
95: case 1:
96: *param_7 = 2;
97: break;
98: case 2:
99: *param_7 = 0;
100: break;
101: case 3:
102: *param_7 = 1;
103: break;
104: case 4:
105: *param_7 = 3;
106: break;
107: case 5:
108: *param_7 = 4;
109: }
110: thunk_FUN_0011f490();
111: if (*param_6 < 0) {
112: *(undefined8 *)(param_1 + 0x648) = 0x616d69204745504a;
113: *(undefined2 *)(param_1 + 0x650) = 0x6567;
114: *(undefined *)(param_1 + 0x652) = 0;
115: *(undefined4 *)(param_1 + 0x6d0) = 1;
116: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
117: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
118: *(undefined8 *)(param_1 + 0x618) = 0x43203a2928337265;
119: *(undefined8 *)(param_1 + 0x620) = 0x746f6e20646c756f;
120: *(undefined8 *)(param_1 + 0x628) = 0x696d726574656420;
121: *(undefined8 *)(param_1 + 0x630) = 0x617362757320656e;
122: *(undefined8 *)(param_1 + 0x638) = 0x7420676e696c706d;
123: *(undefined8 *)(param_1 + 0x640) = 0x20726f6620657079;
124: puVar4 = (undefined4 *)
125: __tls_get_addr(0x7420676e696c706d,0x696d726574656420,0x43203a2928337265,
126: 0x706d6f6365446a74,&PTR_00398fc0);
127: *(undefined8 *)(puVar4 + 0x10) = 0x616d69204745504a;
128: *(undefined2 *)(puVar4 + 0x12) = 0x6567;
129: iVar2 = -1;
130: *(undefined *)((long)puVar4 + 0x4a) = 0;
131: *puVar4 = 0x65446a74;
132: puVar4[1] = 0x706d6f63;
133: puVar4[2] = 0x73736572;
134: puVar4[3] = 0x64616548;
135: puVar4[4] = 0x28337265;
136: puVar4[5] = 0x43203a29;
137: puVar4[6] = 0x646c756f;
138: puVar4[7] = 0x746f6e20;
139: puVar4[8] = 0x74656420;
140: puVar4[9] = 0x696d7265;
141: puVar4[10] = 0x7320656e;
142: puVar4[0xb] = 0x61736275;
143: puVar4[0xc] = 0x696c706d;
144: puVar4[0xd] = 0x7420676e;
145: puVar4[0xe] = 0x20657079;
146: puVar4[0xf] = 0x20726f66;
147: iVar3 = *(int *)(param_1 + 0x5f8);
148: }
149: else {
150: if (*param_7 < 0) {
151: *(undefined4 *)(param_1 + 0x648) = 0x656761;
152: *(undefined4 *)(param_1 + 0x6d0) = 1;
153: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
154: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
155: *(undefined8 *)(param_1 + 0x618) = 0x43203a2928337265;
156: *(undefined8 *)(param_1 + 0x620) = 0x746f6e20646c756f;
157: *(undefined8 *)(param_1 + 0x628) = 0x696d726574656420;
158: *(undefined8 *)(param_1 + 0x630) = 0x726f6c6f6320656e;
159: *(undefined8 *)(param_1 + 0x638) = 0x666f206563617073;
160: *(undefined8 *)(param_1 + 0x640) = 0x6d69204745504a20;
161: puVar4 = (undefined4 *)
162: __tls_get_addr(0x666f206563617073,0x696d726574656420,0x43203a2928337265,
163: 0x706d6f6365446a74,&PTR_00398fc0);
164: puVar4[0x10] = 0x656761;
165: *puVar4 = 0x65446a74;
166: puVar4[1] = 0x706d6f63;
167: puVar4[2] = 0x73736572;
168: puVar4[3] = 0x64616548;
169: puVar4[4] = 0x28337265;
170: puVar4[5] = 0x43203a29;
171: puVar4[6] = 0x646c756f;
172: puVar4[7] = 0x746f6e20;
173: puVar4[8] = 0x74656420;
174: puVar4[9] = 0x696d7265;
175: puVar4[10] = 0x6320656e;
176: puVar4[0xb] = 0x726f6c6f;
177: puVar4[0xc] = 0x63617073;
178: puVar4[0xd] = 0x666f2065;
179: puVar4[0xe] = 0x45504a20;
180: puVar4[0xf] = 0x6d692047;
181: iVar3 = *(int *)(param_1 + 0x5f8);
182: iVar2 = -1;
183: }
184: else {
185: if ((*param_4 < 1) || (*param_5 < 1)) {
186: *(undefined4 *)(param_1 + 0x638) = 0x64616568;
187: *(undefined2 *)(param_1 + 0x63c) = 0x7265;
188: *(undefined *)(param_1 + 0x63e) = 0;
189: *(undefined4 *)(param_1 + 0x6d0) = 1;
190: *(undefined8 *)(param_1 + 0x608) = 0x706d6f6365446a74;
191: *(undefined8 *)(param_1 + 0x610) = 0x6461654873736572;
192: *(undefined8 *)(param_1 + 0x618) = 0x49203a2928337265;
193: *(undefined8 *)(param_1 + 0x620) = 0x642064696c61766e;
194: *(undefined8 *)(param_1 + 0x628) = 0x7574657220617461;
195: *(undefined8 *)(param_1 + 0x630) = 0x206e692064656e72;
196: puVar4 = (undefined4 *)
197: __tls_get_addr(0x7574657220617461,0x49203a2928337265,0x706d6f6365446a74,
198: &PTR_00398fc0);
199: puVar4[0xc] = 0x64616568;
200: *(undefined2 *)(puVar4 + 0xd) = 0x7265;
201: *(undefined *)((long)puVar4 + 0x36) = 0;
202: *puVar4 = 0x65446a74;
203: puVar4[1] = 0x706d6f63;
204: puVar4[2] = 0x73736572;
205: puVar4[3] = 0x64616548;
206: puVar4[4] = 0x28337265;
207: puVar4[5] = 0x49203a29;
208: puVar4[6] = 0x6c61766e;
209: puVar4[7] = 0x64206469;
210: puVar4[8] = 0x20617461;
211: puVar4[9] = 0x75746572;
212: puVar4[10] = 0x64656e72;
213: puVar4[0xb] = 0x206e6920;
214: iVar3 = *(int *)(param_1 + 0x5f8);
215: iVar2 = -1;
216: }
217: else {
218: iVar3 = *(int *)(param_1 + 0x5f8);
219: }
220: }
221: }
222: if (iVar3 == 0) {
223: return iVar2;
224: }
225: }
226: }
227: }
228: return -1;
229: }
230: 
