1: 
2: void FUN_00106ce0(undefined (*param_1) [16],undefined (*param_2) [16],undefined (*param_3) [16])
3: 
4: {
5: undefined8 uVar1;
6: undefined8 uVar2;
7: undefined8 uVar3;
8: undefined8 uVar4;
9: undefined8 uVar5;
10: undefined8 uVar6;
11: undefined auVar7 [16];
12: undefined auVar8 [16];
13: long lVar9;
14: short sVar10;
15: 
16: if ((param_1[8] <= param_3 || param_3[0x10] <= param_1) &&
17: (param_1[8] <= param_2 || param_2[0x10] <= param_1)) {
18: uVar1 = *(undefined8 *)*param_2;
19: auVar7 = *param_3;
20: uVar2 = *(undefined8 *)param_2[1];
21: uVar3 = *(undefined8 *)(*param_2 + 8);
22: uVar4 = *(undefined8 *)(param_2[1] + 8);
23: uVar5 = *(undefined8 *)param_3[1];
24: auVar8 = param_3[1];
25: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
26: uVar6 = *(undefined8 *)param_2[2];
27: *(short *)*param_1 =
28: (short)(int)((float)*(undefined8 *)*param_3 * (float)uVar1 + 16384.5) + -0x4000;
29: *(short *)(*param_1 + 2) =
30: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar1 >> 0x20) + 16384.5) + -0x4000;
31: *(short *)(*param_1 + 4) =
32: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar3 + 16384.5) + -0x4000;
33: *(short *)(*param_1 + 6) =
34: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
35: (float)((ulong)uVar3 >> 0x20) + 16384.5) << 0x10) >>
36: 0x10) + -0x4000;
37: *(short *)(*param_1 + 8) = (short)(int)((float)uVar5 * (float)uVar2 + 16384.5) + -0x4000;
38: *(short *)(*param_1 + 10) = sVar10 + -0x4000;
39: *(short *)(*param_1 + 0xc) =
40: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar4 + 16384.5) << 0x10) >>
41: 0x10) + -0x4000;
42: *(short *)(*param_1 + 0xe) =
43: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar4 >> 0x20) + 16384.5) + -0x4000;
44: uVar1 = *(undefined8 *)(param_2[2] + 8);
45: auVar7 = param_3[2];
46: uVar2 = *(undefined8 *)param_2[3];
47: uVar3 = *(undefined8 *)(param_2[3] + 8);
48: uVar4 = *(undefined8 *)param_3[3];
49: auVar8 = param_3[3];
50: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
51: uVar5 = *(undefined8 *)param_2[4];
52: *(short *)param_1[1] =
53: (short)(int)((float)*(undefined8 *)param_3[2] * (float)uVar6 + 16384.5) + -0x4000;
54: *(short *)(param_1[1] + 2) =
55: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar6 >> 0x20) + 16384.5) + -0x4000;
56: *(short *)(param_1[1] + 4) =
57: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar1 + 16384.5) + -0x4000;
58: *(short *)(param_1[1] + 6) =
59: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
60: (float)((ulong)uVar1 >> 0x20) + 16384.5) << 0x10) >>
61: 0x10) + -0x4000;
62: *(short *)(param_1[1] + 8) = (short)(int)((float)uVar4 * (float)uVar2 + 16384.5) + -0x4000;
63: *(short *)(param_1[1] + 10) = sVar10 + -0x4000;
64: *(short *)(param_1[1] + 0xc) =
65: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar3 + 16384.5) << 0x10) >>
66: 0x10) + -0x4000;
67: *(short *)(param_1[1] + 0xe) =
68: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5) + -0x4000;
69: uVar1 = *(undefined8 *)(param_2[4] + 8);
70: auVar7 = param_3[4];
71: uVar2 = *(undefined8 *)param_2[5];
72: uVar3 = *(undefined8 *)(param_2[5] + 8);
73: uVar4 = *(undefined8 *)param_3[5];
74: auVar8 = param_3[5];
75: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
76: uVar6 = *(undefined8 *)param_2[6];
77: *(short *)param_1[2] =
78: (short)(int)((float)*(undefined8 *)param_3[4] * (float)uVar5 + 16384.5) + -0x4000;
79: *(short *)(param_1[2] + 2) =
80: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar5 >> 0x20) + 16384.5) + -0x4000;
81: *(short *)(param_1[2] + 4) =
82: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar1 + 16384.5) + -0x4000;
83: *(short *)(param_1[2] + 6) =
84: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
85: (float)((ulong)uVar1 >> 0x20) + 16384.5) << 0x10) >>
86: 0x10) + -0x4000;
87: *(short *)(param_1[2] + 8) = (short)(int)((float)uVar4 * (float)uVar2 + 16384.5) + -0x4000;
88: *(short *)(param_1[2] + 10) = sVar10 + -0x4000;
89: *(short *)(param_1[2] + 0xc) =
90: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar3 + 16384.5) << 0x10) >>
91: 0x10) + -0x4000;
92: *(short *)(param_1[2] + 0xe) =
93: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5) + -0x4000;
94: uVar1 = *(undefined8 *)(param_2[6] + 8);
95: auVar7 = param_3[6];
96: uVar2 = *(undefined8 *)param_2[7];
97: uVar3 = *(undefined8 *)(param_2[7] + 8);
98: uVar4 = *(undefined8 *)param_3[7];
99: auVar8 = param_3[7];
100: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
101: *(short *)param_1[3] =
102: (short)(int)((float)*(undefined8 *)param_3[6] * (float)uVar6 + 16384.5) + -0x4000;
103: *(short *)(param_1[3] + 2) =
104: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar6 >> 0x20) + 16384.5) + -0x4000;
105: *(short *)(param_1[3] + 4) =
106: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar1 + 16384.5) + -0x4000;
107: *(short *)(param_1[3] + 6) =
108: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
109: (float)((ulong)uVar1 >> 0x20) + 16384.5) << 0x10) >>
110: 0x10) + -0x4000;
111: *(short *)(param_1[3] + 8) = (short)(int)((float)uVar4 * (float)uVar2 + 16384.5) + -0x4000;
112: *(short *)(param_1[3] + 10) = sVar10 + -0x4000;
113: *(short *)(param_1[3] + 0xc) =
114: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar3 + 16384.5) << 0x10) >>
115: 0x10) + -0x4000;
116: *(short *)(param_1[3] + 0xe) =
117: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5) + -0x4000;
118: uVar1 = *(undefined8 *)param_2[8];
119: uVar2 = *(undefined8 *)(param_2[8] + 8);
120: auVar7 = param_3[8];
121: uVar3 = *(undefined8 *)param_2[9];
122: uVar4 = *(undefined8 *)(param_2[9] + 8);
123: uVar5 = *(undefined8 *)param_3[9];
124: auVar8 = param_3[9];
125: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5);
126: uVar6 = *(undefined8 *)param_2[10];
127: *(short *)param_1[4] =
128: (short)(int)((float)*(undefined8 *)param_3[8] * (float)uVar1 + 16384.5) + -0x4000;
129: *(short *)(param_1[4] + 2) =
130: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar1 >> 0x20) + 16384.5) + -0x4000;
131: *(short *)(param_1[4] + 4) =
132: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar2 + 16384.5) + -0x4000;
133: *(short *)(param_1[4] + 6) =
134: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
135: (float)((ulong)uVar2 >> 0x20) + 16384.5) << 0x10) >>
136: 0x10) + -0x4000;
137: *(short *)(param_1[4] + 8) = (short)(int)((float)uVar5 * (float)uVar3 + 16384.5) + -0x4000;
138: *(short *)(param_1[4] + 10) = sVar10 + -0x4000;
139: *(short *)(param_1[4] + 0xc) =
140: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar4 + 16384.5) << 0x10) >>
141: 0x10) + -0x4000;
142: *(short *)(param_1[4] + 0xe) =
143: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar4 >> 0x20) + 16384.5) + -0x4000;
144: uVar1 = *(undefined8 *)(param_2[10] + 8);
145: auVar7 = param_3[10];
146: uVar2 = *(undefined8 *)param_2[0xb];
147: uVar3 = *(undefined8 *)(param_2[0xb] + 8);
148: uVar4 = *(undefined8 *)param_3[0xb];
149: auVar8 = param_3[0xb];
150: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
151: uVar5 = *(undefined8 *)param_2[0xc];
152: *(short *)param_1[5] =
153: (short)(int)((float)*(undefined8 *)param_3[10] * (float)uVar6 + 16384.5) + -0x4000;
154: *(short *)(param_1[5] + 2) =
155: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar6 >> 0x20) + 16384.5) + -0x4000;
156: *(short *)(param_1[5] + 4) =
157: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar1 + 16384.5) + -0x4000;
158: *(short *)(param_1[5] + 6) =
159: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
160: (float)((ulong)uVar1 >> 0x20) + 16384.5) << 0x10) >>
161: 0x10) + -0x4000;
162: *(short *)(param_1[5] + 8) = (short)(int)((float)uVar4 * (float)uVar2 + 16384.5) + -0x4000;
163: *(short *)(param_1[5] + 10) = sVar10 + -0x4000;
164: *(short *)(param_1[5] + 0xc) =
165: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar3 + 16384.5) << 0x10) >>
166: 0x10) + -0x4000;
167: *(short *)(param_1[5] + 0xe) =
168: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5) + -0x4000;
169: uVar1 = *(undefined8 *)(param_2[0xc] + 8);
170: auVar7 = param_3[0xc];
171: uVar2 = *(undefined8 *)param_2[0xd];
172: uVar3 = *(undefined8 *)(param_2[0xd] + 8);
173: uVar4 = *(undefined8 *)param_3[0xd];
174: auVar8 = param_3[0xd];
175: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
176: uVar6 = *(undefined8 *)param_2[0xe];
177: *(short *)param_1[6] =
178: (short)(int)((float)*(undefined8 *)param_3[0xc] * (float)uVar5 + 16384.5) + -0x4000;
179: *(short *)(param_1[6] + 2) =
180: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar5 >> 0x20) + 16384.5) + -0x4000;
181: *(short *)(param_1[6] + 4) =
182: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar1 + 16384.5) + -0x4000;
183: *(short *)(param_1[6] + 6) =
184: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
185: (float)((ulong)uVar1 >> 0x20) + 16384.5) << 0x10) >>
186: 0x10) + -0x4000;
187: *(short *)(param_1[6] + 8) = (short)(int)((float)uVar4 * (float)uVar2 + 16384.5) + -0x4000;
188: *(short *)(param_1[6] + 10) = sVar10 + -0x4000;
189: *(short *)(param_1[6] + 0xc) =
190: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar3 + 16384.5) << 0x10) >>
191: 0x10) + -0x4000;
192: *(short *)(param_1[6] + 0xe) =
193: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5) + -0x4000;
194: uVar1 = *(undefined8 *)(param_2[0xe] + 8);
195: auVar7 = param_3[0xe];
196: uVar2 = *(undefined8 *)param_2[0xf];
197: uVar3 = *(undefined8 *)(param_2[0xf] + 8);
198: uVar4 = *(undefined8 *)param_3[0xf];
199: auVar8 = param_3[0xf];
200: sVar10 = (short)(int)(SUB164(auVar8 >> 0x20,0) * (float)((ulong)uVar2 >> 0x20) + 16384.5);
201: *(short *)param_1[7] =
202: (short)(int)((float)*(undefined8 *)param_3[0xe] * (float)uVar6 + 16384.5) + -0x4000;
203: *(short *)(param_1[7] + 2) =
204: (short)(int)(SUB164(auVar7 >> 0x20,0) * (float)((ulong)uVar6 >> 0x20) + 16384.5) + -0x4000;
205: *(short *)(param_1[7] + 4) =
206: (short)(int)(SUB164(auVar7 >> 0x40,0) * (float)uVar1 + 16384.5) + -0x4000;
207: *(short *)(param_1[7] + 6) =
208: (short)((ulong)CONCAT24(sVar10,(int)(SUB164(auVar7 >> 0x60,0) *
209: (float)((ulong)uVar1 >> 0x20) + 16384.5) << 0x10) >>
210: 0x10) + -0x4000;
211: *(short *)(param_1[7] + 8) = (short)(int)((float)uVar4 * (float)uVar2 + 16384.5) + -0x4000;
212: *(short *)(param_1[7] + 10) = sVar10 + -0x4000;
213: *(short *)(param_1[7] + 0xc) =
214: (short)((ulong)(uint)((int)(SUB164(auVar8 >> 0x40,0) * (float)uVar3 + 16384.5) << 0x10) >>
215: 0x10) + -0x4000;
216: *(short *)(param_1[7] + 0xe) =
217: (short)(int)(SUB164(auVar8 >> 0x60,0) * (float)((ulong)uVar3 >> 0x20) + 16384.5) + -0x4000;
218: return;
219: }
220: lVar9 = 0;
221: do {
222: *(short *)(*param_1 + lVar9) =
223: (short)(int)(*(float *)(*param_3 + lVar9 * 2) * *(float *)(*param_2 + lVar9 * 2) + 16384.5)
224: + -0x4000;
225: lVar9 = lVar9 + 2;
226: } while (lVar9 != 0x80);
227: return;
228: }
229: 
