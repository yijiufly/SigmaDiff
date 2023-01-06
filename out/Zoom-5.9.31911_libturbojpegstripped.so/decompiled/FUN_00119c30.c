1: 
2: undefined8 FUN_00119c30(code **param_1,undefined8 *param_2)
3: 
4: {
5: long *plVar1;
6: byte bVar2;
7: short sVar3;
8: short sVar4;
9: undefined4 uVar5;
10: code *pcVar6;
11: undefined8 uVar7;
12: undefined *puVar8;
13: undefined8 *puVar9;
14: code **ppcVar10;
15: byte bVar11;
16: int iVar12;
17: long lVar13;
18: uint uVar14;
19: uint uVar15;
20: int iVar16;
21: ulong uVar17;
22: ulong uVar18;
23: uint uVar19;
24: short *psVar20;
25: uint uStack408;
26: ulong auStack360 [3];
27: short asStack336 [144];
28: 
29: lVar13 = (long)*(int *)((long)param_1 + 0x19c);
30: iVar16 = *(int *)(param_1 + 0x23);
31: pcVar6 = param_1[0x3e];
32: uVar5 = *(undefined4 *)(param_1 + 0x35);
33: iVar12 = (*(int *)(param_1 + 0x34) - *(int *)((long)param_1 + 0x19c)) + 1;
34: uVar7 = *(undefined8 *)((long)param_1[5] + 8);
35: *(undefined8 *)(pcVar6 + 0x30) = *(undefined8 *)param_1[5];
36: *(undefined8 *)(pcVar6 + 0x38) = uVar7;
37: if ((iVar16 != 0) && (*(int *)(pcVar6 + 0x80) == 0)) {
38: FUN_00118d20(pcVar6,*(undefined4 *)(pcVar6 + 0x84));
39: lVar13 = (long)*(int *)((long)param_1 + 0x19c);
40: }
41: (**(code **)(pcVar6 + 0x18))
42: (*param_2,&DAT_0018b460 + lVar13 * 4,iVar12,uVar5,asStack336,auStack360);
43: psVar20 = asStack336;
44: if (auStack360[0] != 0) {
45: if (*(int *)(pcVar6 + 0x6c) != 0) {
46: FUN_00118690(pcVar6);
47: }
48: do {
49: uVar15 = 0;
50: uVar17 = auStack360[0];
51: while ((uVar17 & 1) == 0) {
52: uVar15 = uVar15 + 1;
53: uVar17 = uVar17 >> 1 | 0x8000000000000000;
54: }
55: bVar11 = (byte)uVar15;
56: psVar20 = psVar20 + (int)uVar15;
57: sVar3 = *psVar20;
58: sVar4 = psVar20[0x40];
59: uVar14 = uVar15;
60: if (0xf < (int)uVar15) {
61: do {
62: while (*(int *)(pcVar6 + 0x28) != 0) {
63: *(long *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0xa8) + 0x780) =
64: *(long *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0xa8) + 0x780) + 1
65: ;
66: LAB_00119d48:
67: uVar14 = uVar14 - 0x10;
68: if ((int)uVar14 < 0x10) goto LAB_00119ead;
69: }
70: iVar16 = *(int *)(pcVar6 + 0x48);
71: bVar2 = *(byte *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88) + 0x4f0);
72: uVar19 = *(uint *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88) + 0x3c0);
73: if (bVar2 == 0) {
74: ppcVar10 = (code **)**(code ***)(pcVar6 + 0x50);
75: *(undefined4 *)(ppcVar10 + 5) = 0x28;
76: (**ppcVar10)();
77: if (*(int *)(pcVar6 + 0x28) != 0) goto LAB_00119d48;
78: }
79: uStack408 = (char)bVar2 + iVar16;
80: uVar17 = (ulong)((int)(1 << (bVar2 & 0x3f)) - 1U & uVar19) <<
81: (0x18U - (char)uStack408 & 0x3f) | *(ulong *)(pcVar6 + 0x40);
82: uVar19 = uStack408;
83: if (7 < (int)uStack408) {
84: do {
85: while( true ) {
86: uVar18 = uVar17;
87: puVar8 = *(undefined **)(pcVar6 + 0x30);
88: uVar17 = uVar18 >> 0x10 & 0xff;
89: *(undefined **)(pcVar6 + 0x30) = puVar8 + 1;
90: *puVar8 = (char)uVar17;
91: plVar1 = (long *)(pcVar6 + 0x38);
92: *plVar1 = *plVar1 + -1;
93: if (*plVar1 == 0) {
94: puVar9 = *(undefined8 **)(*(long *)(pcVar6 + 0x50) + 0x28);
95: iVar16 = (*(code *)puVar9[3])();
96: if (iVar16 == 0) {
97: ppcVar10 = (code **)**(code ***)(pcVar6 + 0x50);
98: *(undefined4 *)(ppcVar10 + 5) = 0x18;
99: (**ppcVar10)();
100: }
101: *(undefined8 *)(pcVar6 + 0x30) = *puVar9;
102: *(undefined8 *)(pcVar6 + 0x38) = puVar9[1];
103: }
104: if ((int)uVar17 == 0xff) break;
105: LAB_00119dc9:
106: uVar19 = uVar19 - 8;
107: uVar17 = uVar18 << 8;
108: if ((int)uVar19 < 8) goto LAB_00119e90;
109: }
110: puVar8 = *(undefined **)(pcVar6 + 0x30);
111: *(undefined **)(pcVar6 + 0x30) = puVar8 + 1;
112: *puVar8 = 0;
113: plVar1 = (long *)(pcVar6 + 0x38);
114: *plVar1 = *plVar1 + -1;
115: if (*plVar1 != 0) goto LAB_00119dc9;
116: puVar9 = *(undefined8 **)(*(long *)(pcVar6 + 0x50) + 0x28);
117: iVar16 = (*(code *)puVar9[3])();
118: if (iVar16 == 0) {
119: ppcVar10 = (code **)**(code ***)(pcVar6 + 0x50);
120: *(undefined4 *)(ppcVar10 + 5) = 0x18;
121: (**ppcVar10)();
122: }
123: uVar19 = uVar19 - 8;
124: *(undefined8 *)(pcVar6 + 0x30) = *puVar9;
125: *(undefined8 *)(pcVar6 + 0x38) = puVar9[1];
126: uVar17 = uVar18 << 8;
127: } while (7 < (int)uVar19);
128: LAB_00119e90:
129: uVar17 = uVar18 << 8;
130: uStack408 = uStack408 & 7;
131: }
132: uVar14 = uVar14 - 0x10;
133: *(ulong *)(pcVar6 + 0x40) = uVar17;
134: *(uint *)(pcVar6 + 0x48) = uStack408;
135: } while (0xf < (int)uVar14);
136: LAB_00119ead:
137: uVar15 = uVar15 & 0xf;
138: }
139: bVar2 = (&DAT_00179440)[(int)sVar3];
140: if (10 < bVar2) {
141: ppcVar10 = (code **)*param_1;
142: *(undefined4 *)(ppcVar10 + 5) = 6;
143: (**ppcVar10)();
144: }
145: iVar16 = uVar15 * 0x10 + (uint)bVar2;
146: if (*(int *)(pcVar6 + 0x28) == 0) {
147: FUN_00118500(pcVar6,*(undefined4 *)
148: (*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88) +
149: (long)iVar16 * 4),
150: (int)*(char *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0x88) +
151: 0x400 + (long)iVar16));
152: }
153: else {
154: plVar1 = (long *)(*(long *)(pcVar6 + (long)*(int *)(pcVar6 + 0x68) * 8 + 0xa8) +
155: (long)iVar16 * 8);
156: *plVar1 = *plVar1 + 1;
157: }
158: FUN_00118500(pcVar6,(int)sVar4,(uint)bVar2);
159: psVar20 = psVar20 + 1;
160: auStack360[0] = (auStack360[0] >> (bVar11 & 0x3f)) >> 1;
161: } while (auStack360[0] != 0);
162: }
163: if ((psVar20 < asStack336 + iVar12) &&
164: (iVar16 = *(int *)(pcVar6 + 0x6c), *(int *)(pcVar6 + 0x6c) = iVar16 + 1, iVar16 + 1 == 0x7fff))
165: {
166: FUN_00118690(pcVar6);
167: }
168: puVar9 = (undefined8 *)param_1[5];
169: *puVar9 = *(undefined8 *)(pcVar6 + 0x30);
170: puVar9[1] = *(undefined8 *)(pcVar6 + 0x38);
171: iVar16 = *(int *)(param_1 + 0x23);
172: if (iVar16 != 0) {
173: iVar12 = *(int *)(pcVar6 + 0x80);
174: if (*(int *)(pcVar6 + 0x80) == 0) {
175: *(uint *)(pcVar6 + 0x84) = *(int *)(pcVar6 + 0x84) + 1U & 7;
176: iVar12 = iVar16;
177: }
178: *(int *)(pcVar6 + 0x80) = iVar12 + -1;
179: }
180: return 1;
181: }
182: 
