1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
4: 
5: void FUN_00149f10(code **param_1)
6: 
7: {
8: undefined4 uVar1;
9: code *pcVar2;
10: code **ppcVar3;
11: code *pcVar4;
12: undefined8 uVar5;
13: long lVar6;
14: undefined8 *puVar7;
15: ulong uVar8;
16: long *plVar9;
17: uint uVar10;
18: ulong uVar11;
19: ulong uVar12;
20: uint uVar13;
21: ulong uVar14;
22: uint uStack100;
23: ulong uStack64;
24: 
25: pcVar2 = param_1[1];
26: plVar9 = *(long **)(pcVar2 + 0x88);
27: if (plVar9 == (long *)0x0) {
28: plVar9 = *(long **)(pcVar2 + 0x90);
29: uVar11 = 0;
30: uVar12 = 0;
31: if (plVar9 != (long *)0x0) goto LAB_00149fc1;
32: }
33: else {
34: uVar11 = 0;
35: uVar12 = 0;
36: do {
37: while (*plVar9 != 0) {
38: plVar9 = (long *)plVar9[6];
39: if (plVar9 == (long *)0x0) goto LAB_00149f97;
40: }
41: uVar14 = (ulong)*(uint *)(plVar9 + 1) * (ulong)*(uint *)((long)plVar9 + 0xc);
42: uVar12 = uVar12 + (ulong)*(uint *)(plVar9 + 2) * (ulong)*(uint *)((long)plVar9 + 0xc);
43: if (~uVar11 < uVar14) {
44: ppcVar3 = (code **)*param_1;
45: ppcVar3[5] = (code *)0xa00000036;
46: (**ppcVar3)(param_1);
47: }
48: plVar9 = (long *)plVar9[6];
49: uVar11 = uVar11 + uVar14;
50: } while (plVar9 != (long *)0x0);
51: LAB_00149f97:
52: plVar9 = *(long **)(pcVar2 + 0x90);
53: while (plVar9 != (long *)0x0) {
54: LAB_00149fc1:
55: while (*plVar9 == 0) {
56: uVar12 = uVar12 + (ulong)*(uint *)(plVar9 + 2) * (ulong)*(uint *)((long)plVar9 + 0xc) * 0x80
57: ;
58: uVar14 = (ulong)*(uint *)(plVar9 + 1) * (ulong)*(uint *)((long)plVar9 + 0xc) * 0x80;
59: if (~uVar11 < uVar14) {
60: ppcVar3 = (code **)*param_1;
61: ppcVar3[5] = (code *)0xb00000036;
62: (**ppcVar3)(param_1);
63: }
64: plVar9 = (long *)plVar9[6];
65: uVar11 = uVar11 + uVar14;
66: if (plVar9 == (long *)0x0) goto LAB_0014a007;
67: }
68: plVar9 = (long *)plVar9[6];
69: }
70: LAB_0014a007:
71: if (uVar12 != 0) {
72: uVar14 = FUN_0014a5e0(param_1,uVar12,uVar11);
73: uStack64 = 1000000000;
74: if (uVar14 < uVar11) {
75: uStack64 = 1;
76: if (uVar14 / uVar12 != 0) {
77: uStack64 = uVar14 / uVar12;
78: }
79: }
80: plVar9 = *(long **)(pcVar2 + 0x88);
81: while (plVar9 != (long *)0x0) {
82: while (*plVar9 == 0) {
83: uVar13 = *(uint *)(plVar9 + 1);
84: uVar10 = *(uint *)((long)plVar9 + 0xc);
85: if (uStack64 < (long)((ulong)uVar13 - 1) / (long)(ulong)*(uint *)(plVar9 + 2) + 1U) {
86: *(uint *)((long)plVar9 + 0x14) = *(uint *)(plVar9 + 2) * (int)uStack64;
87: FUN_0014a610(param_1,plVar9 + 7,(ulong)uVar10 * (ulong)uVar13);
88: *(undefined4 *)((long)plVar9 + 0x2c) = 1;
89: uVar10 = *(uint *)((long)plVar9 + 0xc);
90: }
91: else {
92: *(uint *)((long)plVar9 + 0x14) = uVar13;
93: }
94: lVar6 = FUN_00149ac0(param_1,1,uVar10);
95: *plVar9 = lVar6;
96: uVar1 = *(undefined4 *)(pcVar2 + 0xa0);
97: *(undefined8 *)((long)plVar9 + 0x1c) = 0;
98: *(undefined4 *)(plVar9 + 5) = 0;
99: *(undefined4 *)(plVar9 + 3) = uVar1;
100: plVar9 = (long *)plVar9[6];
101: if (plVar9 == (long *)0x0) goto LAB_0014a0ce;
102: }
103: plVar9 = (long *)plVar9[6];
104: }
105: LAB_0014a0ce:
106: plVar9 = *(long **)(pcVar2 + 0x90);
107: while (plVar9 != (long *)0x0) {
108: if (*plVar9 == 0) {
109: uStack100 = *(uint *)(plVar9 + 1);
110: uVar11 = (ulong)uStack100;
111: uVar12 = (ulong)*(uint *)((long)plVar9 + 0xc);
112: if (uStack64 < (long)(uVar11 - 1) / (long)(ulong)*(uint *)(plVar9 + 2) + 1U) {
113: *(uint *)((long)plVar9 + 0x14) = *(uint *)(plVar9 + 2) * (int)uStack64;
114: FUN_0014a610(param_1,plVar9 + 7,uVar12 * uVar11 * 0x80);
115: *(undefined4 *)((long)plVar9 + 0x2c) = 1;
116: uStack100 = *(uint *)((long)plVar9 + 0x14);
117: uVar11 = (ulong)uStack100;
118: uVar12 = (ulong)*(uint *)((long)plVar9 + 0xc);
119: }
120: else {
121: *(uint *)((long)plVar9 + 0x14) = uStack100;
122: }
123: pcVar4 = param_1[1];
124: uVar14 = SUB168((ZEXT816(0) << 0x40 | ZEXT816(0x3b9ac9e8)) / ZEXT816(uVar12 * 0x80),0);
125: if (uVar14 == 0) {
126: ppcVar3 = (code **)*param_1;
127: *(undefined4 *)(ppcVar3 + 5) = 0x46;
128: (**ppcVar3)(param_1);
129: }
130: if (uVar11 <= uVar14) {
131: uVar14 = (ulong)uStack100;
132: }
133: *(int *)(pcVar4 + 0xa0) = (int)uVar14;
134: lVar6 = FUN_00148a90(param_1,1,uVar11 * 8);
135: if (uStack100 != 0) {
136: uVar13 = 0;
137: do {
138: pcVar4 = param_1[1];
139: if (uStack100 - uVar13 < (uint)uVar14) {
140: uVar14 = (ulong)(uStack100 - uVar13);
141: }
142: uVar11 = uVar14 * uVar12 * 0x80;
143: if (1000000000 < uVar11) {
144: ppcVar3 = (code **)*param_1;
145: ppcVar3[5] = (code *)0x800000036;
146: (**ppcVar3)(param_1);
147: }
148: if (1000000000 < uVar11 + 0x37) {
149: ppcVar3 = (code **)*param_1;
150: ppcVar3[5] = (code *)0x300000036;
151: (**ppcVar3)(param_1);
152: }
153: puVar7 = (undefined8 *)FUN_0014a5c0(param_1);
154: if (puVar7 == (undefined8 *)0x0) {
155: ppcVar3 = (code **)*param_1;
156: ppcVar3[5] = (code *)0x400000036;
157: (**ppcVar3)(param_1);
158: uVar8 = 0x18;
159: *(ulong *)(pcVar4 + 0x98) = uVar11 + 0x37 + *(long *)(pcVar4 + 0x98);
160: _TURBOJPEG_1.4 = *(undefined8 *)(pcVar4 + 0x80);
161: _DAT_00000010 = 0;
162: _DAT_00000008 = uVar11;
163: *(undefined8 *)(pcVar4 + 0x80) = 0;
164: puVar7 = (undefined8 *)0x18;
165: LAB_0014a281:
166: puVar7 = (undefined8 *)((long)puVar7 + (0x20 - uVar8));
167: }
168: else {
169: *(ulong *)(pcVar4 + 0x98) = uVar11 + 0x37 + *(long *)(pcVar4 + 0x98);
170: uVar5 = *(undefined8 *)(pcVar4 + 0x80);
171: puVar7[1] = uVar11;
172: puVar7[2] = 0;
173: *puVar7 = uVar5;
174: *(undefined8 **)(pcVar4 + 0x80) = puVar7;
175: puVar7 = puVar7 + 3;
176: uVar8 = (ulong)((uint)puVar7 & 0x1f);
177: if (((ulong)puVar7 & 0x1f) != 0) goto LAB_0014a281;
178: }
179: if ((int)uVar14 != 0) {
180: uVar10 = (int)uVar14 + uVar13;
181: do {
182: uVar11 = (ulong)uVar13;
183: uVar13 = uVar13 + 1;
184: *(undefined8 **)(lVar6 + uVar11 * 8) = puVar7;
185: puVar7 = puVar7 + uVar12 * 0x10;
186: } while (uVar13 != uVar10);
187: }
188: } while (uVar13 < uStack100);
189: }
190: uVar1 = *(undefined4 *)(pcVar2 + 0xa0);
191: *plVar9 = lVar6;
192: *(undefined8 *)((long)plVar9 + 0x1c) = 0;
193: *(undefined4 *)(plVar9 + 5) = 0;
194: *(undefined4 *)(plVar9 + 3) = uVar1;
195: }
196: plVar9 = (long *)plVar9[6];
197: }
198: }
199: }
200: return;
201: }
202: 
