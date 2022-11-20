#pragma warning(disable:4996)
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
#include <TlHelp32.h>
#include<time.h>

//这里写的是全局变量
//###############################################################################################################################################
char Xor_str[] = "JNCTF{}";
unsigned int find_table[] = {   3567, 1268, 540, 1745, 1894, 242, 707, 106, 194, 2006, 227,
								3393, 1498, 267, 219, 525, 2988, 1756, 134, 19, 141,
								401, 3846, 1624, 2209, 1644, 1421, 3122, 2998, 194, 2635,
								1292, 22, 122, 1830, 162, 1639, 3997, 7, 1463, 2185,
								3387, 170, 198, 3471, 35, 2399, 3742, 1214, 3698, 2242,
								3834, 1610, 1859, 1864, 3785, 798, 2631, 2675, 1743, 2122,
								3715, 62, 2503, 60, 1407, 3723, 289, 3710, 3052, 575,
								3917, 1598, 1830, 1128, 624, 1336, 1050, 2358, 2349, 2898,
								1743, 60, 931, 2019, 733, 139, 183, 361, 3577, 2997,
								1082, 1038, 1580, 2341, 1551, 853, 1980, 3026, 1003, 1698,
								790, 137, 2786, 2930, 3979, 746, 3664, 2750, 2264, 2555,
								199, 183, 579, 128, 2974, 476, 30, 3683, 2546, 3783,
								616, 1040, 1704, 2506, 2741, 1413, 625, 154, 395, 56,
								4046, 2427, 2350, 42, 1563, 1827, 901, 534, 3263, 27,
								3657, 1933, 1125, 1398, 1812, 2666, 2134, 3168, 3708, 1346,
								975, 803, 32, 3515, 937, 245, 3004, 1237, 500, 2191,
								1450, 3381, 2951, 1765, 176, 23, 462, 101, 2063, 83,
								2448, 398, 160, 1867, 1605, 1680, 556, 1102, 492, 1284,
								529, 3924, 2969, 2464, 2772, 3260, 2100, 3200, 2905, 3559,
								231, 3511, 3136, 174, 1849, 237, 3164, 107, 996, 2763,
								659, 1743, 381, 2383, 3494, 1441, 3679, 63, 3909, 1058,
								3221, 1075, 828, 204, 1872, 3051, 3806, 1174, 1758, 2178,
								640, 328, 74, 3575, 3768, 2777, 1015, 2126, 1555, 184,
								2602, 3089, 1041, 2690, 443, 299, 1995, 378, 1814, 214,
								372, 579, 2764, 3595, 2748, 2708, 2582, 80, 1992, 1781,
								3767, 73, 1120, 2975, 2558 };
unsigned char xor_table[] = { 0x80, 0xac, 0x7c, 0xa8, 0xef, 0xe0, 0x58, 0xed, 0x94, 0xad, 0x0, 0x99, 0xdd, 0x29, 0x6b, 0xb1, 0xf7, 0x6d, 0xd5, 0xf9, 0x21, 0xdf, 0xc7, 0xb9, 0xe, 0xb5, 0xe9, 0x1a, 0x6c, 0xd, 0x26, 0x5e, 0x97, 0x36, 0xcd, 0xba, 0x69, 0xca, 0x95, 0x15, 0xf2, 0xef, 0xa8, 0x1a, 0x6e, 0x5b, 0x0, 0x81 };

unsigned char FA(unsigned char b);
unsigned char FB(unsigned char b);
unsigned char FC(unsigned char b);
unsigned char FD(unsigned char b);
unsigned char FE(unsigned char b);
unsigned char Ff(unsigned char b);
void Cipher(unsigned char* input, unsigned char* output, unsigned char* w);		//加密 
void InvCipher(unsigned char* input, unsigned char* output, unsigned char* w);	//解密 

static unsigned char AesSbox[16 * 16] =
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static unsigned char AesiSbox[16 * 16] =
{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
static unsigned char AesRcon[11 * 4] =
{
	0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00,
	0x80, 0x00, 0x00, 0x00,
	0x1b, 0x00, 0x00, 0x00,
	0x36, 0x00, 0x00, 0x00
};


unsigned char  FA(unsigned char b) { if (b < 0x80) return (b << 1); else return ((b << 1) ^ (0x1b)); }
unsigned char  FB(unsigned char b) { return  FA(b) ^ b; }
unsigned char  FC(unsigned char b) { return  FA(FA(FA(b))) ^ b; }
unsigned char  FD(unsigned char b) { return  FA(FA(FA(b))) ^ FA(b) ^ b; }
unsigned char  FE(unsigned char b) { return  FA(FA(FA(b))) ^ FA(FA(b)) ^ b; }
unsigned char  Ff(unsigned char b) { return  FA(FA(FA(b))) ^ FA(FA(b)) ^ FA(b); }

//这里写的是函数头
//###############################################################################################################################################
unsigned char* GetProces();
void a1is127(char* input);
void a1is62(char* input);
unsigned char* a1is43(char* input);

unsigned long AES128_CBC_Decrypt(unsigned char* input_buff, unsigned long InputLen, unsigned char* p_key, unsigned char* output_buff);
unsigned long AES128_CBC_Encrypt(unsigned char* input_buff, unsigned long InputLen, unsigned char* p_key, unsigned char* output_buff);
void  InvCipher(unsigned char* input, unsigned char* output, unsigned char* exp_key);
void  Cipher(unsigned char* input, unsigned char* output, unsigned char* exp_key);

void ror7rol(unsigned char* str, int n, int w);
unsigned char* b64encode(unsigned char* str, int choice);
unsigned char* fini_xor(char* str);
unsigned char* find_nxt_table(unsigned char* first_encrypt, int len);

unsigned char* key_2_base_Table(char* arr, char* key);
unsigned char* alp_WJNY_encrypt(char* text, char* key);

void log_succ();
void log_error();

void creatStr(int choice);
//###############################################################################################################################################

//整个都是一个AES加密解密函数
//################################################################################################################################################
void  Cipher(unsigned char* input, unsigned char* output, unsigned char* exp_key)
{
	int i, j;
	int round;
	unsigned char ttt[4 * 4];
	unsigned char State[4][4];
	for (i = 0; i < 16; i++)  State[i % 4][i / 4] = input[i];
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = State[i][j] ^ exp_key[4 * j + i];
	for (round = 1; round <= 9; round++)
	{
		for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = AesSbox[State[i][j]];
		for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)ttt[4 * i + j] = State[i][j];
		for (i = 1; i < 4; i++)for (j = 0; j < 4; j++)
		{
			if (i == 1)State[i][j] = ttt[4 * i + (j + 1) % 4]; else if (i == 2)State[i][j] = ttt[4 * i + (j + 2) % 4]; else if (i == 3)State[i][j] = ttt[4 * i + (j + 3) % 4];
		}
		for (j = 0; j < 4; j++)  for (i = 0; i < 4; i++)	ttt[4 * i + j] = State[i][j];
		for (j = 0; j < 4; j++)
		{
			State[0][j] = FA(ttt[0 + j]) ^ FB(ttt[4 * 1 + j]) ^ ttt[4 * 2 + j] ^ ttt[4 * 3 + j];
			State[1][j] = ttt[0 + j] ^ FA(ttt[4 * 1 + j]) ^ FB(ttt[4 * 2 + j]) ^ ttt[4 * 3 + j];
			State[2][j] = ttt[0 + j] ^ ttt[4 * 1 + j] ^ FA(ttt[4 * 2 + j]) ^ FB(ttt[4 * 3 + j]);
			State[3][j] = FB(ttt[0 + j]) ^ ttt[4 * 1 + j] ^ ttt[4 * 2 + j] ^ FA(ttt[4 * 3 + j]);
		}
		for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = State[i][j] ^ exp_key[4 * ((round * 4) + j) + i];
	}
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = AesSbox[State[i][j]];
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)ttt[4 * i + j] = State[i][j];
	for (i = 1; i < 4; i++)for (j = 0; j < 4; j++)
	{
		if (i == 1)State[i][j] = ttt[4 * i + (j + 1) % 4]; else if (i == 2)State[i][j] = ttt[4 * i + (j + 2) % 4]; else if (i == 3)State[i][j] = ttt[4 * i + (j + 3) % 4];
	}
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = State[i][j] ^ exp_key[4 * (40 + j) + i];
	for (i = 0; i < 16; i++)output[i] = State[i % 4][i / 4];
}

void  InvCipher(unsigned char* input, unsigned char* output, unsigned char* exp_key)
{
	int round;
	int i, j;
	unsigned char ttt[4 * 4];
	unsigned char State[4][4];
	for (i = 0; i < 16; i++)State[i % 4][i / 4] = input[i];
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = State[i][j] ^ exp_key[4 * (40 + j) + i];
	for (round = 9; round >= 1; round--)
	{
		for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)ttt[4 * i + j] = State[i][j];
		for (i = 1; i < 4; i++)for (j = 0; j < 4; j++)
		{
			if (i == 1)State[i][j] = ttt[4 * i + (j + 3) % 4]; else if (i == 2)State[i][j] = ttt[4 * i + (j + 2) % 4]; else if (i == 3)State[i][j] = ttt[4 * i + (j + 1) % 4];
		}
		for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = AesiSbox[State[i][j]];
		for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = State[i][j] ^ exp_key[4 * ((round * 4) + j) + i];
		for (i = 0; i < 4; i++)for (j = 0; j < 4; j++) ttt[4 * i + j] = State[i][j];
		for (j = 0; j < 4; j++)
		{
			State[0][j] = Ff(ttt[j]) ^ FD(ttt[4 + j]) ^ FE(ttt[4 * 2 + j]) ^ FC(ttt[4 * 3 + j]);
			State[1][j] = FC(ttt[j]) ^ Ff(ttt[4 + j]) ^ FD(ttt[4 * 2 + j]) ^ FE(ttt[4 * 3 + j]);
			State[2][j] = FE(ttt[j]) ^ FC(ttt[4 + j]) ^ Ff(ttt[4 * 2 + j]) ^ FD(ttt[4 * 3 + j]);
			State[3][j] = FD(ttt[j]) ^ FE(ttt[4 + j]) ^ FC(ttt[4 * 2 + j]) ^ Ff(ttt[4 * 3 + j]);
		}
	}
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)ttt[4 * i + j] = State[i][j];
	for (i = 1; i < 4; i++)for (j = 0; j < 4; j++)
	{
		if (i == 1)State[i][j] = ttt[4 * i + (j + 3) % 4]; else if (i == 2)State[i][j] = ttt[4 * i + (j + 2) % 4]; else if (i == 3)State[i][j] = ttt[4 * i + (j + 1) % 4];
	}
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = AesiSbox[State[i][j]];
	for (j = 0; j < 4; j++)for (i = 0; i < 4; i++)State[i][j] = State[i][j] ^ exp_key[4 * j + i];
	for (i = 0; i < 16; i++)output[i] = State[i % 4][i / 4];
}

unsigned long AES128_CBC_Encrypt(unsigned char* input_buff, unsigned long InputLen, unsigned char* p_key, unsigned char* output_buff)
{
	unsigned long OutLength = 0;
	long i, j;
	unsigned char* lpCurInBuff = input_buff;
	unsigned char* lpCurOutBuff = output_buff;
	long blocknum = InputLen / 16;
	long leftnum = InputLen % 16;
	unsigned char iv[20] = "1234567890ABCDEF";//偏移量 
	int row;
	unsigned char temp[4];
	unsigned char ex_key[16 * 15];
	for (row = 0; row < 4; row++)       //拷贝seed 密钥
	{
		ex_key[4 * row + 0] = *(p_key + 4 * row);
		ex_key[4 * row + 1] = *(p_key + 4 * row + 1);
		ex_key[4 * row + 2] = *(p_key + 4 * row + 2);
		ex_key[4 * row + 3] = *(p_key + 4 * row + 3);
	}
	for (row = 4; row < 44; row++)
	{
		temp[0] = ex_key[4 * row - 4];     //当前列的前一列  
		temp[1] = ex_key[4 * row - 3];
		temp[2] = ex_key[4 * row - 2];
		temp[3] = ex_key[4 * row - 1];
		if (row % 4 == 0)
		{
			unsigned char exchange_buff = 0;
			exchange_buff = temp[0];
			temp[0] = AesSbox[16 * (temp[1] >> 4) + (temp[1] & 0x0f)];
			temp[1] = AesSbox[16 * (temp[2] >> 4) + (temp[2] & 0x0f)];
			temp[2] = AesSbox[16 * (temp[3] >> 4) + (temp[3] & 0x0f)];
			temp[3] = AesSbox[16 * (exchange_buff >> 4) + (exchange_buff & 0x0f)];

			temp[0] = temp[0] ^ AesRcon[4 * (row / 4) + 0];
			temp[1] = temp[1] ^ AesRcon[4 * (row / 4) + 1];
			temp[2] = temp[2] ^ AesRcon[4 * (row / 4) + 2];
			temp[3] = temp[3] ^ AesRcon[4 * (row / 4) + 3];
		}
		ex_key[4 * row + 0] = ex_key[4 * (row - 4) + 0] ^ temp[0];
		ex_key[4 * row + 1] = ex_key[4 * (row - 4) + 1] ^ temp[1];
		ex_key[4 * row + 2] = ex_key[4 * (row - 4) + 2] ^ temp[2];
		ex_key[4 * row + 3] = ex_key[4 * (row - 4) + 3] ^ temp[3];
	}
	for (i = 0; i < blocknum; i++)
	{
		for (j = 0; j < 16; j++)lpCurOutBuff[j] = lpCurInBuff[j] ^ iv[j];
		Cipher(lpCurOutBuff, lpCurOutBuff, ex_key);
		memcpy(iv, lpCurOutBuff, 16);
		lpCurInBuff += 16;
		lpCurOutBuff += 16;
		OutLength += 16;
	}
	if (leftnum)
	{
		unsigned char inbuff[16];
		memset(inbuff, 16 - leftnum, 16);
		memcpy(inbuff, lpCurInBuff, leftnum);
		for (j = 0; j < 16; j++)lpCurOutBuff[j] = inbuff[j] ^ iv[j];
		Cipher(lpCurOutBuff, lpCurOutBuff, ex_key);
		memcpy(iv, lpCurOutBuff, 16);
		lpCurOutBuff += 16;
		OutLength += 16;
	}
	else
	{
		unsigned char extrabuff[16];
		memset(extrabuff, 16, 16);
		for (j = 0; j < 16; j++)lpCurOutBuff[j] = extrabuff[j] ^ iv[j];
		Cipher(lpCurOutBuff, lpCurOutBuff, ex_key);
		memcpy(iv, lpCurOutBuff, 16);
		OutLength += 16;
	}
	return OutLength;
}

unsigned long AES128_CBC_Decrypt(unsigned char* input_buff, unsigned long InputLen, unsigned char* p_key, unsigned char* output_buff)
{
	unsigned long OutLength = 0;
	long blocknum = InputLen / 16;
	long leftnum = InputLen % 16;
	long i, j;
	unsigned char temp[16];
	unsigned char iv[20] = "1234567890ABCDEF";
	unsigned char* pCurInBuf = input_buff;
	unsigned char* pCurOutBuf = output_buff;
	int row;
	if (leftnum)
	{
		return 0;
	}
	unsigned char ex_key[16 * 15];
	for (row = 0; row < 4; row++)
	{
		ex_key[4 * row + 0] = *(p_key + 4 * row);
		ex_key[4 * row + 1] = *(p_key + 4 * row + 1);
		ex_key[4 * row + 2] = *(p_key + 4 * row + 2);
		ex_key[4 * row + 3] = *(p_key + 4 * row + 3);
	}
	for (row = 4; row < 44; row++)
	{
		temp[0] = ex_key[4 * row - 4];     //当前列的前一列  
		temp[1] = ex_key[4 * row - 3];
		temp[2] = ex_key[4 * row - 2];
		temp[3] = ex_key[4 * row - 1];
		if (row % 4 == 0)
		{
			unsigned char exchange_buff = 0;
			exchange_buff = temp[0];
			temp[0] = AesSbox[16 * (temp[1] >> 4) + (temp[1] & 0x0f)];
			temp[1] = AesSbox[16 * (temp[2] >> 4) + (temp[2] & 0x0f)];
			temp[2] = AesSbox[16 * (temp[3] >> 4) + (temp[3] & 0x0f)];
			temp[3] = AesSbox[16 * (exchange_buff >> 4) + (exchange_buff & 0x0f)];
			temp[0] = temp[0] ^ AesRcon[4 * (row / 4) + 0];
			temp[1] = temp[1] ^ AesRcon[4 * (row / 4) + 1];
			temp[2] = temp[2] ^ AesRcon[4 * (row / 4) + 2];
			temp[3] = temp[3] ^ AesRcon[4 * (row / 4) + 3];
		}
		ex_key[4 * row + 0] = ex_key[4 * (row - 4) + 0] ^ temp[0];
		ex_key[4 * row + 1] = ex_key[4 * (row - 4) + 1] ^ temp[1];
		ex_key[4 * row + 2] = ex_key[4 * (row - 4) + 2] ^ temp[2];
		ex_key[4 * row + 3] = ex_key[4 * (row - 4) + 3] ^ temp[3];
	}
	for (i = 0; i < blocknum; i++)
	{
		InvCipher(pCurInBuf, pCurOutBuf, ex_key);
		for (j = 0; j < 16; j++)
		{
			pCurOutBuf[j] = pCurOutBuf[j] ^ iv[j];
		}
		memcpy(iv, pCurInBuf, 16);
		if (i == (blocknum - 1))
		{
			memset(temp, 0, 16);
			if (pCurOutBuf[15] != 0x10)
			{
				if (pCurOutBuf[15] < 0x10)
				{
					OutLength = InputLen - pCurOutBuf[15];
					memcpy(temp, pCurOutBuf, 16 - pCurOutBuf[15]);
					memcpy(pCurOutBuf, temp, 16);
				}
				else
					break;
			}
			else
			{
				OutLength = InputLen - 16;
				memcpy(pCurOutBuf, temp, 16);
			}
		}
		pCurInBuf += 16;
		pCurOutBuf += 16;
	}
	return OutLength;
}

//################################################################################################################################################

//这个函数根据传进去的数组和对应的编号，通过异或来解密生成字符串
void creatStr(int choice)
{
	//unsigned char v1[] = { 70, 99, 126, 127, 118, 49, 71, 116, 99, 120, 119, 120, 114, 112, 101, 120, 126, 127, 49, 82, 126, 117, 116,0 };
	//unsigned char v2[] = { 4, 7, 6, 1, 0, 3, 2, 13, 12, 5, 116, 119, 118, 113, 112, 115,0 };
	//unsigned char v3[] = { 83, 65, 4, 74, 65, 65, 64, 4, 80, 75, 4, 82, 65, 86, 77, 66, 93, 4, 93, 75, 81, 86, 4, 77, 64, 65, 74, 80, 77, 80, 93, 30, 4 ,0 };
	//unsigned char v4[] = { 99, 72, 82, 67, 84, 6, 82, 78, 67, 6, 66, 67, 82, 71, 69, 78, 67, 66, 6, 80, 67, 84, 79, 64, 79, 69, 71, 82, 79, 73, 72, 6, 69, 73, 66, 67, 28, 6,0 };
	//unsigned char v5[] = { 121, 69, 76, 72, 90, 76, 9, 76, 71, 93, 76, 91, 9, 80, 70, 92, 91, 9, 96, 109, 9, 71, 92, 68, 75, 76, 91, 19, 9,0 };

	char v1[] = { 70, 99, 126, 127, 118, 49, 71, 116, 99, 120, 119, 120, 114, 112, 101, 120, 126, 127, 49, 82, 126, 117, 116,0 };
	char v2[] = { 4, 7, 6, 1, 0, 3, 2, 13, 12, 5, 116, 119, 118, 113, 112, 115,0 };
	char v3[] = { 83, 65, 4, 74, 65, 65, 64, 4, 80, 75, 4, 82, 65, 86, 77, 66, 93, 4, 93, 75, 81, 86, 4, 77, 64, 65, 74, 80, 77, 80, 93, 30, 4 ,0 };
	char v4[] = { 99, 72, 82, 67, 84, 6, 82, 78, 67, 6, 66, 67, 82, 71, 69, 78, 67, 66, 6, 80, 67, 84, 79, 64, 79, 69, 71, 82, 79, 73, 72, 6, 69, 73, 66, 67, 28, 6,0 };
	char v5[] = { 121, 69, 76, 72, 90, 76, 9, 76, 71, 93, 76, 91, 9, 80, 70, 92, 91, 9, 96, 109, 9, 71, 92, 68, 75, 76, 91, 19, 9,0 };


	int i = 0;
	switch (choice)
	{
	case 0x11:			//wrong flag这是main里的判断不对, Wrong Verification Code
		for (i = 0; i < strlen(v1); i++)
		{
			printf("%c", v1[i] ^ 0x11);
		}
		break;
	case 0x35:   //1234567890ABCDEF5
		for (i = 0; i < strlen(v2) - 1; i++)
		{
			printf("%c", v2[i] ^ 0x35);
		}
		break;
	case 0x24:
		for (i = 0; i < strlen(v3) - 1; i++)
		{
			printf("%c", v3[i] ^ 0x24);
		}
		break;
	case 0x26:   //we need to verify your identity:
		for (i = 0; i < strlen(v4) - 1; i++)
		{
			printf("%c", v4[i] ^ 0x26);
		}
		break;
	case 0x29:   //Please enter your ID number:
		for (i = 0; i < strlen(v5) - 1; i++)
		{
			printf("%c", v5[i] ^ 0x29);
		}
		break;
	default:
		break;
	}

}

char* helpGetProcName(char character)
{
	char* s = (char*)malloc(0x30);
	char ida[] = {0x8, 0x5, 0x0, 0x57, 0x55, 0x4f, 0x4, 0x19, 0x4};
	char x64[] = {0x1a, 0x54, 0x56, 0x6, 0x0, 0x5, 0x4c, 0x7, 0x1a, 0x7};
	char not[] = {0xd, 0xc, 0x17, 0x6, 0x13, 0x2, 0x7, 0x4d, 0x6, 0x1b, 0x6};
	char calc[] = {0x27, 0x5, 0x8, 0x7, 0x11, 0x8, 0x5, 0x10, 0xb, 0x16, 0x4a, 0x1, 0x1c, 0x1};
	int i=0;
	if(character == 'a')
	{
		for (i=0;i<9;i++)
			s[i] = ida[i] ^ character;
		s[i] = '\0';
		return s;
	}else if (character == 'b')
	{
		for (i=0;i<10;i++)
			s[i] = x64[i] ^ character;
		s[i] = '\0';
		return s;
	}else if(character == 'c')
	{
		for (i=0;i<11;i++)
			s[i] = not[i] ^ character;
		s[i] = '\0';
		return s;
	}else if(character == 'd')
	{
		for (i=0;i<14;i++)
			s[i] = calc[i] ^ character;
		s[i] = '\0';
		return s;
	}
	return s;
}


//获取进程列表,寻找notepad.exe和Calculator.exe的进程，同时寻找是否存在ida64.exe或者x64dbg.exe,根据notepad.exe和Calculator.exe合成密钥
unsigned char* GetProces()
{
	unsigned char* res = (char*)malloc(128);
	char CreatKey[48];
	int flag = 127;
	int countProcess = 0;												//当前进程数量计数变量
	PROCESSENTRY32 currentProcess;										//存放快照进程信息的一个结构体
	currentProcess.dwSize = sizeof(currentProcess);						//在使用这个结构之前，先设置它的大小
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  //给系统内的所有进程拍一个快照
	
	char *disass = helpGetProcName('a');
	char *dbgger1 = helpGetProcName('b');
	char *calc =  helpGetProcName('c');
	char *note = helpGetProcName('d');

	// char *disass = (char*)malloc(0x20);
	// char *dbgger1 = (char*)malloc(0x20);;
	// char *calc = (char*)malloc(0x20);;
	// char *note = (char*)malloc(0x20);;
	// strcpy(disass, "ida64.exe");
	// strcpy(dbgger1, "x64dbg.exe");
	// strcpy(note,"notepad.txt");
	// strcpy(calc, "Calculator.exe");


	if (hProcess == INVALID_HANDLE_VALUE)
		exit(0);

	int bMore = Process32First(hProcess, &currentProcess);	//获取第一个进程信息

	//先判断有没有这俩进程
	while (bMore)
	{
		if (!strcmp(disass, currentProcess.szExeFile) || !strcmp(dbgger1, currentProcess.szExeFile))
		{
			flag = 0x62;
				break;
		}

		if (!strcmp(calc, currentProcess.szExeFile))
		{
			flag = 0x23;
		}

		if (!strcmp(note, currentProcess.szExeFile))
		{
			// printf("%x\n", flag);
			flag += 0x20;
			if (flag == 0x43)
				break;
		}

		bMore = Process32Next(hProcess, &currentProcess);	//遍历下一个
		countProcess++;
	}

	// printf("0x%x\n", flag);
	switch (flag)
	{
		//这是没有找到合适的进程.或者是程序出现意外
	case 127:case 0x23:
		creatStr(0x24);
		//printf("we need to verify your identity: "); //这里输入的是flag，就是第一个输入
		scanf("%40s", CreatKey);
		a1is127(CreatKey);
		return 0;
		break;

		// 这是符合条件的函数
	case 0x43:
		creatStr(0x26);
		//printf("Enter the detached verification code: "); //这里输入的是flag，就是第一个输入
		scanf("%40s", CreatKey);
		return (a1is43(CreatKey));
		break;

		//这是存在调试进程的函数
	case 0x62:
		creatStr(0x29);
		//printf("Please enter your ID number: "); //这里输入的是flag，就是第一个输入
		scanf("%40s", CreatKey);
		a1is62(CreatKey);
		return 0;
		break;

		//存在其他情况则为报错
	default:
		FreeConsole();
		/*printf("run the default\n");*/
		log_error();
		exit(0);
		break;
	}
	CloseHandle(hProcess);	//清除hProcess句柄
}

//满足进程环境就执行这个函数
unsigned char* a1is43(char* input)
{
	int outlen = 0;
	unsigned char* new_arr = (unsigned char*)malloc(128);
	//char input[41];
	char key[] = "hmxxjxhJtlocfagv";
	char key_1[] = "cybersecurityRAT";
	unsigned char aes_back[96];
	unsigned char out_data[96];
	unsigned char* bs64 = (char*)malloc(128);

	if (strlen(input) ^ 40)												//判断输入长度是否满足40字节长度
	{
		log_error();
		exit(0);
	}
	else
	{
		outlen = AES128_CBC_Encrypt(input, strlen(input), key, aes_back);	//将输入先进行aes加密，得到密文数组。
		new_arr = find_nxt_table(aes_back, 48);								//根据密文数组对应出新的密文来。新密文的长度是48
		outlen = AES128_CBC_Decrypt(new_arr, 96, key_1, out_data);
		bs64 = b64encode(out_data, 0x7);									//对新的密文解密的结果进行base64编码，不变表
		bs64[48] = '\0';
		//puts(bs64);
		return bs64;
	}
}

//根据第一步得到的输入的进行aes之后的密文先去重初始化，然后进行查表获得第二阶段的密文
unsigned char* find_nxt_table(unsigned char* first_encrypt, int len)
{
	unsigned char* tmparr = (char*)malloc(64);
	int arr[] = { 3, 8, 1, 4 };
	int i;

	for (i = 0; i < len; i++)
	{
		first_encrypt[i] ^= arr[i % 4];
	}
	first_encrypt[23] ^= 0x91;
	//数组去重(初始化)完毕

	for (i = 0; i < len; i++)
	{
		tmparr[i] = first_encrypt[i] ^ xor_table[i];				//这里存在数组的越界访问
	}
	return tmparr;
}

//base64加密函数，自带判断变表；key = HigaIsa
unsigned char* b64encode(unsigned char* str, int choice)//根据choic的值来判断码表
{
	size_t len;
	size_t str_len;
	unsigned char* res = NULL;
	int i, j;
	unsigned char* base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	switch ((char)choice)
	{
	case 0x77:
		base64_table = key_2_base_Table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "HigSha");
		break;
	case 0x55:
		base64_table = key_2_base_Table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "NoPlasd");
		break;
	default:
		base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		break;
	}

	str_len = strlen(str);
	if (str_len % 3 == 0)
		len = str_len / 3 * 4;
	else
		len = (str_len / 3 + 1) * 4;

	res = malloc(sizeof(unsigned char) * len + 1);
	res[len] = '\0';

	//以3个8位字符为一组进行编码  
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		res[i] = base64_table[str[j] >> 2]; //取出第一个字符的前6位并找出对应的结果字符  
		res[i + 1] = base64_table[(str[j] & 0x3) << 4 | (str[j + 1] >> 4)];
		res[i + 2] = base64_table[(str[j + 1] & 0xf) << 2 | (str[j + 2] >> 6)];
		res[i + 3] = base64_table[str[j + 2] & 0x3f]; 
	}

	switch (str_len % 3)
	{
	case 1:
		res[i - 2] = '=';
		res[i - 1] = '=';
		break;
	case 2:
		res[i - 1] = '=';
		break;
	}
	res[i] = '\0';
	return res;
}

//最后的异或函数
unsigned char* fini_xor(char* str)
{
	int i = 0;
	char re[52];
	unsigned char* fini = (char*)malloc(128);
	while (*str)
	{
		re[i] = *str ^ Xor_str[i % strlen(Xor_str)];
		//printf("%d, ", re[i]);
		*str++;
		i++;
	}
	re[i] = '\0';
	return b64encode(re, 0x99);
}

//输入不对就调用这个函数
void log_error()
{
	MessageBox(NULL, TEXT("Something Wrong But I can`t tell you."), TEXT("ERROR"), 0);
	exit(0);
}

void log_succ()
{
	MessageBox(NULL, TEXT("you're a script kiddie!!!"), TEXT("YES"), 0);
	exit(0);
}

//当存在调试进程的时候，会执行到这个函数;这个函数是不可逆的
void a1is62(char* input)
{
	int i;
	char arr[64];
	int randxor[128] = { 0 };
	int c[3] = { 0x77,0x55 };
	int sec = time((time_t*)NULL);
	char* ptr;
	char cmp[64] = { 102, 117, 99, 107, 102, 117, 99, 107, 102, 117, 99, 107, 102, 117, 99, 107, 102, 117, 99, 107, 72, 65, 72, 65, 72, 65, 72, 65, 72, 72, 65, 72, 65, 72, 65, 72 };

	ptr = (char*)malloc(128);

	printf("you input is %s\n", input);
	srand(0);
	for (i = 0; i < strlen(input); i++)
	{
		randxor[i] = rand() & 0xff;
	}

	for (i = 0; i < strlen(input); i++)
	{
		arr[i] = input[i] ^ randxor[i];
	}

	ptr = b64encode(arr, c[sec % 2]);
	for (i = 0; i < strlen(input); i++)
	{
		if (ptr[i] != cmp[i])
			log_error();
	}
	log_succ();
}

//当他没有扫描到进程的时候，会到这个函数;这里的假的flag是   club_for_CyberSecurity_not_4_CTF
void a1is127(char* input)
{
	/*
		输入和key进行异或，之后进行一个ror，然后和一直数组进行比较，成功就成功，失败就失败。
	*/
	// int crypt_Arry[33] = { 0xac, 0xf6, 0x3f, 0x14, 0x3d, 0xb, 0xb, 0x35, 0x12, 0x14, 0x3f, 0xc, 0x33, 0x41, 0x19, 0x13, 0x1, 0x18, 0x16, 0x2e, 0x39, 0x2e, 0x19, 0x0, 0x39, 0x47, 0x15, 0x42, 0x3d, 0x2e, 0x30, 0x1 };
	char crypt_Arry[33] = {0xa6, 0xeb, 0xe7, 0x82, 0xa7, 0x61, 0x61, 0xa6, 0x42, 0x82, 0xe7, 0x81, 0x66, 0x28, 0x23, 0x62, 0x20, 0x3, 0xc2, 0xc5, 0x27, 0xc5, 0x23, 0x0, 0x39, 0x47, 0x15, 0x42, 0x3d, 0x2e, 0x30, 0x1};
	char key[13] = "V3JvbmdGMWFn";
	char* flag;
	flag = (char*)malloc(48);
	char str[36];

	for (int i = 0; i < 32; i++)
	{
		str[i] = key[i % strlen(key)] ^ input[i];
	}

	srand(0);
	ror7rol(str, rand() % 7, 0x47);

	for (int i = 0; i < 32; i++)
	{
		// printf("0x%x, ", str[i]&0xff);
		if (crypt_Arry[i] != str[i])
		{
			log_error();
			exit(0);
		}
	}
	log_succ();
}

//根据n来确定循环的位数；根据w来确定ror还是rol
void ror7rol(unsigned char* str, int n, int w)
{
	char tmp;
	int i = 0;

	//0x47 ----> ror
	//0x74 ----> rol
	switch (w)
	{
	case 0x47:		//ROR
		if (n < 8)
		{

			for (; i < strlen(str); i++)
			{
				tmp = ((str[i] >> n) | (str[i] << (8 - n))) & 0xff;
				str[i] = tmp;
			}
		}
		else
		{
			n = n % 8;
			int i = 0;
			for (; i < strlen(str); i++)
			{
				tmp = ((str[i] >> n) | (str[i] << (8 - n))) & 0xff;
				str[i] = tmp;
			}
		}
		break;
	case 0x74:
		if (n < 8)
		{

			for (; i < strlen(str); i++)
			{
				tmp = ((str[i] << n) | (str[i] >> (8 - n))) & 0xff;
				str[i] = tmp;
			}
		}
		else
		{
			n = n % 8;
			int i = 0;
			for (; i < strlen(str); i++)
			{
				tmp = ((str[i] << n) | (str[i] >> (8 - n))) & 0xff;
				str[i] = tmp;
			}
		}
		break;
	default:
		printf("CHOICE ERROR\n");
		break;
	}
}

//一个关于key对base的table进行的变换
unsigned char* key_2_base_Table(char* arr, char* key)
{
	int key_len = strlen(key);
	int arr_len = strlen(arr);
	int i, j = 0;

	char tmp = '0';

	char* tmp1 = (char*)malloc(96);
	char* arry = (char*)malloc(96);
	char* Key = (char*)malloc(96);
	Key[0] = 0;
	strcpy(arry, arr);
	strcpy(Key, key);

	//init the key
	if (key_len % 2 == 0)//if the len of key is oushu, 采用两两交换
	{
		for (i = 0; i < key_len - 1; i++)
		{
			if (key[i] <= 'Z' && key[i] >= 'A')
				tmp = arr[key[i] - 'A'];
			else if (key[i] <= 'z' && key[i] >= 'a')
				tmp = arr[key[i] - 'a' + 26];

			if (key[i + 1] <= 'Z' && key[i + 1] >= 'A')
			{
				arry[key[i] - 'A' + 26] = arry[key[i + 1] - 'A'];
				arry[key[i + 1] - 'A' + 26] = tmp;
			}
			else if (key[i + 1] <= 'z' && key[i + 1] >= 'a')
			{
				arry[key[i] - 'a' + 26] = arry[key[i + 1] - 'a' + 26];
				arry[key[i + 1] - 'a' + 26] = tmp;
			}
		}
		arry[64] = '\0';
	}
	else	//采用12，23，34，45，这样的交换
	{
		for (i = 0; i < key_len - 1; i++)
		{
			Key[i] = Key[i + 1] - 1;
			j += Key[i];
		}
		j %= 46;

		//printf("\n----%d---\n", j);

		strncpy(tmp1, arry + j, 64 - j);
		//puts(tmp1);
		for (i = 0; i < j; i++)
		{
			tmp1[i + 64 - j] = arry[i];
		}
		tmp1[64] = '\0';
		//puts(tmp1);
		//printf("\n----%s---\n", Key);
	}
	return arry;
}

//这里是对维吉尼亚密码的改变，特定位置的数字的偏移是一样的。这个函数只能变换铭文，相当于是交换了顺序，所以应该在初始加密的过程。
unsigned char* alp_WJNY_encrypt(char* text, char* key)
{
	int i;
	int off_arry[64] = { 0 };
	char* re = (char*)malloc(96);
	int tmp;

	//先根据key算出来每一个铭文对应的偏移
	for (i = 0; i < strlen(text); i++)
	{
		if (text[i] != 95)//如果铭文遇到_
		{
			tmp = *(key + i % strlen(key));
			if (tmp <= 'z' && tmp >= 'a')
			{
				off_arry[i] = tmp - 'a';
			}
			else if (tmp <= 'Z' && tmp >= 'A')
			{
				off_arry[i] = tmp - 'A';
			}
			else
			{
				off_arry[i] = tmp - 0;
			}
		}
		else
		{
			off_arry[i] = 14;
		}
	}

	//根据算出来的偏移来变换铭文

	for (i = 0; i < strlen(text); i++)
	{
		tmp = *(text + i);
		if (tmp <= 'z' && tmp >= 'a') //小写操作
		{
			if (tmp + off_arry[i] > 'z')
			{
				re[i] = tmp + off_arry[i] - 'z' + 'a';
			}
			else if (tmp + off_arry[i] <= 'z')
			{
				re[i] = tmp + off_arry[i];
			}
		}
		else if (tmp <= 'Z' && tmp >= 'A') //大写操作
		{
			if (tmp + off_arry[i] > 'Z')
			{
				re[i] = tmp + off_arry[i] - 'Z' + 'A';
			}
			else if (tmp + off_arry[i] <= 'Z')
			{
				re[i] = tmp + off_arry[i];
			}
		}
		else
		{
			re[i] = tmp;
		}
	}
	re[i] = '\0';
	return re;
}

int main()
{
	int i;
	unsigned char* re = (unsigned char*)malloc(65);
	unsigned char* re_1 = (unsigned char*)malloc(65);
	char* re_2 = (char*)malloc(65);
	unsigned char cmp[] = {  0x88, 0x2a, 0xaa, 0x2a, 0x4b, 0x8a,
					0xca, 0x29, 0x69, 0x2a, 0xa9, 0x4d,
					0x6c, 0x4a, 0x29, 0xee, 0x69, 0x0d,
					0x07, 0xac, 0x29, 0x2d, 0x06, 0xea,
					0xa8, 0xaa, 0x6e, 0xee, 0x48, 0x48,
					0x86, 0xe6, 0xe9, 0x28, 0xee, 0x0f,
					0x49, 0x8a, 0x6d, 0x2e, 0xe8, 0x4f,
					0x6d, 0xed, 0xa9, 0x4d, 0x6e, 0xae,
					0x09, 0xee, 0x86, 0xae, 0x0a, 0x4f, 0xee,
					0x46, 0xe8, 0x0b, 0x07, 0xee, 0x4b, 0x0f,
					0x29, 0x2f, 0x00 };
	re = GetProces();
	re_1 = alp_WJNY_encrypt(re, "KDJdqpcm");

	re_2 = fini_xor(re_1);

	ror7rol(cmp, 5, 0x47);

	for (i = 0; i < 64; i++)
	{
		if (cmp[i] != re_2[i])
		{
			creatStr(0x11);
			return 0;
		}
	}
	MessageBox(NULL, TEXT("I can't believe you got here"), TEXT("OH NO!!!!!"), 0);
	return 0;
}