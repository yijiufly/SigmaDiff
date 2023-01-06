1: 
2: void FUN_00122bc0(code **param_1,int param_2)
3: 
4: {
5: uint *puVar1;
6: int *piVar2;
7: undefined4 *puVar3;
8: undefined4 *puVar4;
9: int iVar5;
10: long lVar6;
11: uint uVar7;
12: int iVar8;
13: undefined4 uVar9;
14: undefined4 uVar10;
15: undefined4 uVar11;
16: uint uVar12;
17: code **ppcVar13;
18: code *pcVar14;
19: undefined8 *__src;
20: long lVar15;
21: undefined8 *puVar16;
22: undefined8 *puVar17;
23: uint uVar18;
24: uint uVar19;
25: long lVar20;
26: ulong uVar21;
27: long lVar22;
28: undefined8 *puVar23;
29: code *pcVar24;
30: int iVar25;
31: int iVar26;
32: long lVar27;
33: undefined8 *puVar28;
34: undefined8 *puVar29;
35: bool bVar30;
36: long lStack176;
37: 
38: if (param_2 != 0) {
39: ppcVar13 = (code **)*param_1;
40: *(undefined4 *)(ppcVar13 + 5) = 4;
41: (**ppcVar13)();
42: }
43: ppcVar13 = (code **)(**(code **)param_1[1])(param_1,1,0x70);
44: param_1[0x38] = (code *)ppcVar13;
45: *ppcVar13 = FUN_00122630;
46: if (*(int *)(param_1[0x3c] + 0x10) == 0) {
47: pcVar24 = param_1[0xb];
48: ppcVar13[1] = FUN_00122670;
49: if (0 < *(int *)((long)param_1 + 0x4c)) {
50: lVar27 = 1;
51: do {
52: puVar1 = (uint *)(pcVar24 + 0x1c);
53: piVar2 = (int *)(pcVar24 + 8);
54: pcVar24 = pcVar24 + 0x60;
55: pcVar14 = (code *)(**(code **)(param_1[1] + 0x10))
56: (param_1,1,
57: (long)((ulong)*puVar1 * 8 * (long)*(int *)(param_1 + 0x27)) /
58: (long)*piVar2 & 0xffffffff,
59: *(undefined4 *)((long)param_1 + 0x13c));
60: ppcVar13[lVar27 + 1] = pcVar14;
61: iVar5 = (int)lVar27;
62: lVar27 = lVar27 + 1;
63: } while (*(int *)((long)param_1 + 0x4c) != iVar5 && iVar5 <= *(int *)((long)param_1 + 0x4c));
64: }
65: }
66: else {
67: uVar7 = *(uint *)((long)param_1 + 0x13c);
68: ppcVar13[1] = FUN_00122930;
69: lVar27 = (**(code **)param_1[1])
70: (param_1,1,(long)(int)(*(int *)((long)param_1 + 0x4c) * 5 * uVar7) << 3);
71: pcVar24 = param_1[0xb];
72: if (0 < *(int *)((long)param_1 + 0x4c)) {
73: iVar8 = uVar7 * 2;
74: lStack176 = 1;
75: iVar5 = uVar7 * 4;
76: puVar29 = (undefined8 *)(lVar27 + 0x10);
77: lVar20 = (long)iVar5;
78: lVar6 = lVar20 * 8;
79: puVar28 = (undefined8 *)(lVar27 + lVar6);
80: lVar27 = (long)iVar8;
81: do {
82: puVar16 = puVar28 + -lVar20;
83: __src = (undefined8 *)
84: (**(code **)(param_1[1] + 0x10))
85: (param_1,1,
86: (long)((ulong)*(uint *)(pcVar24 + 0x1c) * 8 *
87: (long)*(int *)(param_1 + 0x27)) / (long)*(int *)(pcVar24 + 8) &
88: 0xffffffff,uVar7 * 3);
89: pcVar14 = (code *)memcpy(puVar28 + ((int)uVar7 - lVar20),__src,(long)(int)(uVar7 * 3) * 8);
90: if (0 < (int)uVar7) {
91: puVar23 = __src + lVar27;
92: if (((((uVar7 < 0x21 || puVar28 < puVar29 && (lVar6 != -0x10 && -1 < lVar6 + 0x10)) ||
93: puVar28 < __src + lVar27 + 2 && puVar23 < puVar29 + lVar20) ||
94: puVar16 < __src + lVar27 + 2 && puVar23 < puVar29) ||
95: puVar28 < __src + 2 && __src < puVar29 + lVar20) ||
96: (__src < puVar29 && puVar16 < __src + 2)) {
97: puVar16 = __src + lVar27;
98: puVar23 = puVar28;
99: do {
100: puVar17 = puVar16 + 1;
101: puVar23[-lVar20] = *puVar16;
102: *puVar23 = puVar16[-lVar27];
103: puVar16 = puVar17;
104: puVar23 = puVar23 + 1;
105: } while (puVar17 != __src + (ulong)(uVar7 - 1) + lVar27 + 1);
106: }
107: else {
108: uVar21 = (ulong)puVar23 >> 3;
109: uVar19 = (uint)uVar21 & 1;
110: iVar25 = 0;
111: if (2 - ((uVar21 & 1) == 0) <= uVar7 - 1) {
112: bVar30 = (uVar21 & 1) != 0;
113: if (bVar30) {
114: puVar29[-2] = *puVar23;
115: *puVar28 = *__src;
116: }
117: uVar18 = 0;
118: uVar12 = uVar7 - uVar19;
119: lVar22 = (ulong)uVar19 * 8;
120: lVar15 = 0;
121: do {
122: puVar3 = (undefined4 *)((long)__src + lVar15 + lVar27 * 8 + lVar22);
123: uVar9 = puVar3[1];
124: uVar10 = puVar3[2];
125: uVar11 = puVar3[3];
126: uVar18 = uVar18 + 1;
127: puVar4 = (undefined4 *)((long)puVar16 + lVar15 + lVar22);
128: *puVar4 = *puVar3;
129: puVar4[1] = uVar9;
130: puVar4[2] = uVar10;
131: puVar4[3] = uVar11;
132: puVar3 = (undefined4 *)((long)__src + lVar15 + lVar22);
133: uVar9 = puVar3[1];
134: uVar10 = puVar3[2];
135: uVar11 = puVar3[3];
136: puVar4 = (undefined4 *)((long)puVar16 + lVar15 + lVar22 + lVar6);
137: *puVar4 = *puVar3;
138: puVar4[1] = uVar9;
139: puVar4[2] = uVar10;
140: puVar4[3] = uVar11;
141: lVar15 = lVar15 + 0x10;
142: } while (uVar18 < uVar12 >> 1);
143: iVar25 = (uint)bVar30 + (uVar12 & 0xfffffffe);
144: if (uVar12 == (uVar12 & 0xfffffffe)) goto LAB_00122f9e;
145: }
146: puVar16[iVar25] = __src[iVar8 + iVar25];
147: iVar26 = iVar25 + 1;
148: puVar16[iVar5 + iVar25] = __src[iVar25];
149: if (iVar26 < (int)uVar7) {
150: puVar16[iVar26] = __src[iVar26 + iVar8];
151: puVar16[iVar26 + iVar5] = __src[iVar26];
152: }
153: }
154: }
155: LAB_00122f9e:
156: pcVar24 = pcVar24 + 0x60;
157: puVar28 = puVar28 + (int)(uVar7 * 5);
158: puVar29 = puVar29 + (int)(uVar7 * 5);
159: ppcVar13[lStack176 + 1] = pcVar14;
160: iVar25 = (int)lStack176;
161: lStack176 = lStack176 + 1;
162: } while (iVar25 < *(int *)((long)param_1 + 0x4c));
163: }
164: }
165: return;
166: }
167: 
