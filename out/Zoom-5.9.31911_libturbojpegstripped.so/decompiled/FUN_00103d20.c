1: 
2: undefined8 FUN_00103d20(long param_1,long param_2)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: undefined2 *puVar5;
10: uint uVar6;
11: int iVar7;
12: uint uVar8;
13: int iVar9;
14: int iVar10;
15: int iVar11;
16: int iVar12;
17: int iVar13;
18: int iVar14;
19: int iStack116;
20: uint uStack84;
21: long lStack80;
22: int iStack72;
23: 
24: lVar3 = *(long *)(param_1 + 0x1c8);
25: uVar6 = *(int *)(param_1 + 0x140) - 1;
26: iStack116 = *(int *)(lVar3 + 0x18);
27: uVar8 = *(int *)(param_1 + 0x168) - 1;
28: iVar13 = *(int *)(lVar3 + 0x1c);
29: if (iVar13 <= iStack116) {
30: LAB_00104255:
31: *(int *)(lVar3 + 0x10) = *(int *)(lVar3 + 0x10) + 1;
32: FUN_00103400(param_1);
33: return 1;
34: }
35: iVar9 = iStack116 << 3;
36: uStack84 = *(uint *)(lVar3 + 0x14);
37: if (uVar8 < uStack84) goto LAB_001040c6;
38: do {
39: do {
40: if (0 < *(int *)(param_1 + 0x144)) {
41: iStack72 = 0;
42: iVar13 = 0;
43: lStack80 = param_1;
44: do {
45: lVar4 = *(long *)(lStack80 + 0x148);
46: if (uStack84 < uVar8) {
47: iVar14 = *(int *)(lVar4 + 0x34);
48: }
49: else {
50: iVar14 = *(int *)(lVar4 + 0x44);
51: }
52: iVar2 = *(int *)(lVar4 + 0x40);
53: if (0 < *(int *)(lVar4 + 0x38)) {
54: iVar12 = 0;
55: do {
56: while ((uVar6 < *(uint *)(lVar3 + 0x10) || uVar6 == *(uint *)(lVar3 + 0x10) &&
57: (*(int *)(lVar4 + 0x48) == iStack116 + iVar12 ||
58: *(int *)(lVar4 + 0x48) < iStack116 + iVar12))) {
59: lVar1 = lVar3 + (long)iVar13 * 8;
60: FUN_0013bed0(*(undefined8 *)(lVar1 + 0x20),(long)*(int *)(lVar4 + 0x34) << 7);
61: iVar10 = *(int *)(lVar4 + 0x34);
62: if (0 < iVar10) {
63: puVar5 = *(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + -1) * 8);
64: **(undefined2 **)(lVar1 + 0x20) = *puVar5;
65: if ((((iVar10 != 1) &&
66: (**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 1) * 8) = *puVar5,
67: iVar10 != 2)) &&
68: ((**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 2) * 8) = *puVar5,
69: iVar10 != 3 &&
70: ((((**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 3) * 8) = *puVar5,
71: iVar10 != 4 &&
72: (**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 4) * 8) = *puVar5,
73: iVar10 != 5)) &&
74: (**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 5) * 8) = *puVar5,
75: iVar10 != 6)) &&
76: ((**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 6) * 8) = *puVar5,
77: iVar10 != 7 &&
78: (**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 7) * 8) = *puVar5,
79: iVar10 != 8)))))))) &&
80: (**(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 8) * 8) = *puVar5,
81: iVar10 != 9)) {
82: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + 9) * 8) = *puVar5;
83: }
84: }
85: LAB_00103e20:
86: iVar13 = iVar13 + iVar10;
87: iVar10 = iVar12 + 1;
88: iVar12 = iVar12 + 1;
89: if (*(int *)(lVar4 + 0x38) <= iVar10) goto LAB_00104070;
90: }
91: (**(code **)(*(long *)(param_1 + 0x1e8) + 8))
92: (param_1,lVar4,*(undefined8 *)(param_2 + (long)*(int *)(lVar4 + 4) * 8),
93: *(undefined8 *)(lVar3 + 0x20 + (long)iVar13 * 8),iVar9 + iVar12 * 8,
94: uStack84 * iVar2,iVar14,iVar9);
95: iVar10 = *(int *)(lVar4 + 0x34);
96: if (iVar10 <= iVar14) goto LAB_00103e20;
97: lVar1 = lVar3 + (long)(iVar13 + iVar14) * 8;
98: FUN_0013bed0(*(undefined8 *)(lVar1 + 0x20),(long)(iVar10 - iVar14) << 7,
99: iVar10 - iVar14);
100: iVar10 = *(int *)(lVar4 + 0x34);
101: if ((((iVar10 <= iVar14) ||
102: (**(undefined2 **)(lVar1 + 0x20) =
103: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar13 + iVar14 + -1) * 8),
104: iVar10 <= iVar14 + 1)) ||
105: (iVar7 = iVar13 + iVar14 + 1,
106: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
107: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8),
108: iVar10 <= iVar14 + 2)) ||
109: ((iVar7 = iVar13 + iVar14 + 2,
110: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
111: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8),
112: iVar10 <= iVar14 + 3 ||
113: (iVar7 = iVar13 + iVar14 + 3,
114: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
115: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8),
116: iVar10 <= iVar14 + 4)))) goto LAB_00103e20;
117: iVar7 = iVar13 + iVar14 + 4;
118: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
119: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8);
120: if (iVar10 <= iVar14 + 5) goto LAB_00103e20;
121: iVar7 = iVar14 + 5 + iVar13;
122: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
123: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8);
124: if (iVar10 <= iVar14 + 6) goto LAB_00103e20;
125: iVar7 = iVar14 + 6 + iVar13;
126: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
127: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8);
128: if (iVar10 <= iVar14 + 7) goto LAB_00103e20;
129: iVar7 = iVar14 + 7 + iVar13;
130: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
131: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8);
132: if (iVar10 <= iVar14 + 8) goto LAB_00103e20;
133: iVar7 = iVar14 + 8 + iVar13;
134: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
135: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8);
136: if (iVar10 <= iVar14 + 9) goto LAB_00103e20;
137: iVar7 = iVar14 + 9 + iVar13;
138: iVar13 = iVar13 + iVar10;
139: iVar11 = iVar12 + 1;
140: iVar10 = *(int *)(lVar4 + 0x38);
141: **(undefined2 **)(lVar3 + 0x20 + (long)iVar7 * 8) =
142: **(undefined2 **)(lVar3 + 0x20 + (long)(iVar7 + -1) * 8);
143: iVar12 = iVar12 + 1;
144: } while (iVar11 < iVar10);
145: }
146: LAB_00104070:
147: iStack72 = iStack72 + 1;
148: lStack80 = lStack80 + 8;
149: } while (*(int *)(param_1 + 0x144) != iStack72 && iStack72 <= *(int *)(param_1 + 0x144));
150: }
151: iVar13 = (**(code **)(*(long *)(param_1 + 0x1f0) + 8))(param_1,lVar3 + 0x20);
152: if (iVar13 == 0) {
153: *(int *)(lVar3 + 0x18) = iStack116;
154: *(uint *)(lVar3 + 0x14) = uStack84;
155: return 0;
156: }
157: uStack84 = uStack84 + 1;
158: } while (uStack84 <= uVar8);
159: iVar13 = *(int *)(lVar3 + 0x1c);
160: LAB_001040c6:
161: iStack116 = iStack116 + 1;
162: iVar9 = iVar9 + 8;
163: *(undefined4 *)(lVar3 + 0x14) = 0;
164: if (iVar13 <= iStack116) goto LAB_00104255;
165: uStack84 = 0;
166: } while( true );
167: }
168: 
