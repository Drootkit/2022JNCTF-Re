#include<stdio.h>
#include <stdint.h>  
#include<string.h>
#include <stdlib.h>
#include <memory.h>

char str8[9]="00000000"; //两个辅助用字符串
char str6[7]="000000";

char junk[17]  = {0};
char flag[] = "JNCTF{WA_HO_great";

char trash[]="okxvznpjfhus";


char* to_bin8(int a)//转化为八位的二进制数
{
    memset(str8,48,9);
    str8[8]=0;
    int i=7;
    while(i>=0)
    {
        str8[i]=a%2+48;
        a=a/2;
        i--;
    }
    return str8;
}
char* to_bin6(int a)//转化为六位的二进制数
{
    memset(str8,48,6);
    str6[6]=0;
    int i=5;
    while(i>=0)
    {
        str6[i]=a%2+48;
        a=a/2;
        i--;
    }
    return str6;
}


char *base64_decode(char *str)//接收要解密的字符串
{

    int table[]={0,0,0,0,0,0,0,0,0,0,0,0,	//根据base64表，以字符找到对应的十进制数据 ，这里是int类型，移位的时候要转换成char地址。
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,62,0,0,0,
    		 63,52,53,54,55,56,57,58,
    		 59,60,61,0,0,0,0,0,0,0,0,
    		 1,2,3,4,5,6,7,8,9,10,11,12,
    		 13,14,15,16,17,18,19,20,21,
    		 22,23,24,25,0,0,0,0,0,0,26,
    		 27,28,29,30,31,32,33,34,35,
    		 36,37,38,39,40,41,42,43,44,
    		 45,46,47,48,49,50,51
    	       };

	int len;
	int str_len;
	char *decodestr;
	int i,j;
	len=strlen(str);	//获取密文长度，必然是4的倍数。
	if(strstr(str,"=="))	//strstr函数获取字符串位置，要去除掉补加的'='的个数才是真正加密后的密文
		str_len=len/4*3-2;		
	else if (strstr(str,"="))
		str_len=len/4*3-1;
	else
		str_len=len/4*3;
	decodestr=malloc(sizeof(char)*str_len+1);//因为C语言不像python一样可以直接+=来添加字符串，所以要用列表，这里是为列表赋予足够的加密字符空间，加1是因为后面的'\0'结束符。
	decodestr[str_len]='\0';		//写入结束符，那么后面'='不用用全0替换了，因为'='高2位是0，不会影响。
	for(i=0,j=0;i<len-1;j+=3,i+=4)//开始4*6变3*8的拆分循环，i<len-1是因为最后一个字符是'\0'，输入字符4个为1组。值得注意的是就算最后有补位用的'='，但是由于'='高2位为0，而且前面有decodestr[str_len]='\0';的截断，所以'='最后不会影响解密结果。        
	{
		decodestr[j]=((char)table[str[i]]) << 2 | ((char)table[str[i+1]]) >> 4;	//4*6变3*8的第一个拆分，table是int地址，所以要转换为char地址才可以按字符取。按4位一组，str[i]的00xxxxxx的8位地址把前面2位0移掉，剩6位。str[i+1]的00xxxxxx后4位移动掉，剩下00xx，实质上是除去前面00只剩下xx两个字符，总共8个字符。           
		decodestr[j+1]=((char)table[str[i+1]]) << 4 | ((char)table[str[i+2]]) >> 2;	//按4位一组，str[i+1]的00xxxxxx的8位地址把前面4位移掉，剩4位。str[i+2]的00xxxxxx后2位移动掉，剩下00xxxx，实质上是除去前面00只剩下xxxx4个字符，总共8个字符。           
		decodestr[j+2]=((char)table[str[i+2]]) << 6 | ((char)table[str[i+3]]);	//按4位一组，str[i+2]的00xxxxxx的8位地址把前面6位移掉，剩2位。str[i+3]的00xxxxxx全部保留，实质上是除去前面00只剩下xxxxxx6个字符，总共8个字符。           
	}
	return decodestr;
}

  

typedef struct _RC4INFO
{
	unsigned char s_box[256];
	unsigned char t_box[256];
}RC4_INFO,*PRC4_INFO;			//定义 RC4 中要用到的 S-Box 和临时向量 T，封装在结构体中并给正常别名和指针别名。 
 
 
void rc4_init(PRC4_INFO prc4,unsigned char key[],unsigned int keylen)
{
	int i=0;
	int j=0;
	unsigned char tmp;
	if(prc4==NULL)
	{
		return;
	}
	
	/*
	初始化存储0-255字节的Sbox(其实就是一个数组)
	填充key到256个字节数组中称为Tbox(你输入的key不满256个字节则初始化到256个字节)
	*/ 
	for(i=0;i<256;i++)
	{
		prc4->s_box[i] = i;
		prc4->t_box[i] = key[i % keylen];	//如果密钥的长度是256字节，就直接把密钥的值赋给k，否则，轮转地将密钥的每个字节赋给k 
	}
	
	//交换s[i]与s[j]   i 从0开始一直到255下标结束. j是 s[i]与T[i]组合得出的下标
	for(i=0;i<256;i++)
	{
		j=(j+prc4->s_box[i]+prc4->t_box[i])%256;
		//开始交换
		tmp=prc4->s_box[i];
		prc4->s_box[i]=prc4->s_box[j];
		prc4->s_box[j]=tmp;
	}
 } 
 

void rc4_crypt(unsigned char data[],unsigned int datalen,unsigned char key[],unsigned int keylen)	//参数分别是要加密的数据、要加密的数据长度、加密数据所用的Key、加密数据所用的key长度
{
	int dn=0;	//data[n]的意思
	int i=0;
	int j=0;	//i j分别用于交换sbox[i] 和 sbox[j]
	int t=0;	//t = s[i] +s[j]
	unsigned char tmp;
	
	RC4_INFO rc4;		//这里定义前面的结构题 
	rc4_init(&rc4,key,keylen);		//在加密函数中调用初始化函数，就省去了其它代码中出现的要保存初始化 sBox 的现象了.
	
	for(dn=0;dn<datalen;dn++)
	{
		//i确保S-box的每个元素都得到处理，j保证S-box的搅乱是随机的。
		i=(i+1)%256;
		j=(j+rc4.s_box[i])%256;
		
		//交换 s_box[i] 和 s_box[j]
		tmp=rc4.s_box[i];
		rc4.s_box[i] = rc4.s_box[j];
		rc4.s_box[j] = tmp;
		
		//交换完之后 再把s[i] + s[j]的组合当做下标再去异或.
		t = (rc4.s_box[i] + rc4.s_box[j]) % 256;
		data[dn] ^= rc4.s_box[t];
	 } 
}
 
void EntryBuffer(unsigned char data[],unsigned int datalen)
{
	unsigned char key[]="pjrHeldsadf";
	rc4_crypt(data,datalen,key,sizeof(key)/sizeof(key[0]));
}
 



int rc4(char Hell[])
{

    EntryBuffer((unsigned char*)Hell,17); //加第一次调用就是加密 
 //   EntryBuffer((unsigned char*)Hell,17); //由于异或运算的对合性，RC4加密解密使用同一套算法。
    return 0;
}



int B[4] = {31373031,30353831,73656375,72697479};
 

void tea(int A[2])
{
	int j;
	unsigned int v0 = A[0],v1 = A[1],sum = 0,delta = 0x9E3779B9;
	for(j=0;j<32;j++){
	
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + B[sum & 3]);
	
		sum += delta;
	
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + B[(sum >> 11) & 3]);
	
	}
	A[0] = v0;
	A[1] = v1;
}


int cut(char v1[],char v2[], char input[])
{
	int i=0;
	for(;i<17;i++)v1[i] = input[i];
//	v1[i] = '\0';
	for(;i<33;i++)v2[i-17] = input[i];
//	v2[i] = '\0';
	printf("%s\n",v1);
	printf("%s\n",v2);
	return 0;
}

void unk_40011E()
{
	strcpy(flag,junk);
}

char *base64_encode(char *str)	//接收要加密的字符串
{
	int str_len; //获取输入的字符的长度，用于后续是否是3的倍数的操作
	int len;	//不足3的倍数是直接下表添加'='
	int i,j;	//用于后续3位一组为单位拆分3*8为4*6的后续操作
	char *encodestr;	//定义用于接受加密后的字符串
	char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; //定义base64的基本表单元素，用指针是因为C语言的字符串没法像python一样可以直接对字符串进行非地址的截取。
	str_len=strlen(str);	//获取输入的字符串长度
	if (str_len % 3 == 0)
		len=(str_len/3)*4;	//如果输入字符是3的倍数，就不用补0,那按照3拆4的规则，加密后的字符串的长度就是len
	else
		len=((str_len/3)+1)*4;	//这里的str_len/3会取整数部分，如果输入的不是3的倍数，比如多一个就是4,多两个也是4。
	encodestr=malloc(sizeof(char)*len+1);	//因为C语言不像python一样可以直接+=来添加字符串，所以要用列表，这里是为列表赋予足够的加密字符空间，加1是因为后面的'\0'结束符。
	encodestr[len]='\0';	//写入结束符
	for(i=0,j=0;i<len-1;j+=3,i+=4)	//开始3*8变4*6的拆分循环，i<len-1是因为最后一个字符是'\0'，输入字符3个为1组。值得注意的是如果输入字符不是3的倍数，那么最后一组,str[j+1]，str[j+2]中依旧会赋值，但是赋的值会被后面switch语句覆盖，所以结果没有影响。            
	{
		encodestr[i]=base64_table[str[j]>>2];	//3*8变4*6的第一个拆分，base64_table前面说了是指针操作，所以可以按字符取。8位一个字符往右移动2位，剩余6位，得出第一个加密下标。
		encodestr[i+1]=base64_table[(str[j]&0x3)<<4 | str[j+1]>>4];	//这里空间折叠可能更好理解，以前的做题经验中 '|' 可以让两边移位同时进行。这里str[j]&0x3取第一个8位的最后2位向前移动4位变成6位中头2位，同时str[j+1]>>4把自身8位中4位向右移动了，那么str[j]8位空间字符剩下2位在前头，str[j+1]8位空间中字符剩下4位在后头，所以合在一起就是6位。
		encodestr[i+2]=base64_table[(str[j+1]&0xf)<<2 | str[j+2]>>6];	//同理，str[j+1]剩下4位向千移动2位变成6位中的头4位，str[j+2]>>6向右移动6位剩余两位，作为6位中的末尾2位。
		encodestr[i+3]=base64_table[str[j+2]&0x3f];	//这里直接与0x3f取6位，不能用<<2，我也暂时不懂                                
	}	
	switch(str_len%3)		//用switch给不足3的最后一组赋值'='，来覆盖前面str[j+1]和str[j+2]生成的但是不改存在的字符。
	{
		case 1:
			encodestr[i-2]='=';
			encodestr[i-1]='=';
			break;
		case 2:
			encodestr[i-1]='=';
			break;
	}
	return encodestr;
 }


 
typedef struct
{
    unsigned int count[2];
    unsigned int state[4];
    unsigned char buffer[64];
}MD5_CTX;
 
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac) \
          { \
          a += F(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
#define GG(a,b,c,d,x,s,ac) \
          { \
          a += G(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
#define HH(a,b,c,d,x,s,ac) \
          { \
          a += H(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
#define II(a,b,c,d,x,s,ac) \
          { \
          a += I(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen);
void MD5Final(MD5_CTX *context,unsigned char digest[16]);
void MD5Transform(unsigned int state[4],unsigned char block[64]);
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len);
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len);
 
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
 
void MD5Init(MD5_CTX *context)
{
     context->count[0] = 0;
     context->count[1] = 0;
     context->state[0] = 0x67452301;
     context->state[1] = 0xEFCDAB89;
     context->state[2] = 0x98BADCFE;
     context->state[3] = 0x10325476;
}
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
    unsigned int i = 0,index = 0,partlen = 0;
    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
 
    context->count[0] += inputlen << 3;
    if(context->count[0] < (inputlen << 3))
       context->count[1]++;
    context->count[1] += inputlen >> 29;
 
    if(inputlen >= partlen){
       memcpy(&context->buffer[index],input,partlen);
       MD5Transform(context->state,context->buffer);
       for(i = partlen;i+64 <= inputlen;i+=64)
           MD5Transform(context->state,&input[i]);
       index = 0;
    }else {
        i = 0;
    }
    memcpy(&context->buffer[index],&input[i],inputlen-i);
}
void MD5Final(MD5_CTX *context,unsigned char digest[16])
{
    unsigned int index = 0,padlen = 0;
    unsigned char bits[8];
    index = (context->count[0] >> 3) & 0x3F;
    padlen = (index < 56)?(56-index):(120-index);
    MD5Encode(bits,context->count,8);
    MD5Update(context,PADDING,padlen);
    MD5Update(context,bits,8);
    MD5Encode(digest,context->state,16);
}
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len) {
         output[j] = input[i] & 0xFF;
         output[j+1] = (input[i] >> 8) & 0xFF;
         output[j+2] = (input[i] >> 16) & 0xFF;
         output[j+3] = (input[i] >> 24) & 0xFF;
         i++;
         j+=4;
    }
}
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
     unsigned int i = 0,j = 0;
     while(j < len){
           output[i] = (input[j]) |
                       (input[j+1] << 8) |
                       (input[j+2] << 16) |
                       (input[j+3] << 24);
           i++;
           j+=4;
     }
}
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
     unsigned int a = state[0];
     unsigned int b = state[1];
     unsigned int c = state[2];
     unsigned int d = state[3];
     unsigned int x[64];
     MD5Decode(x,block,64);
     FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
     FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
     FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
     FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
     FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
     FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
     FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
     FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
     FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
     FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
     FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
     FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
     FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
     FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
     FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
     FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */
 
     /* Round 2 */
     GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
     GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
     GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
     GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
     GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
     GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
     GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
     GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
     GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
     GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
     GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
     GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
     GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
     GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
     GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
     GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */
 
     /* Round 3 */
     HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
     HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
     HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
     HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
     HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
     HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
     HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
     HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
     HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
     HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
     HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
     HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
     HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
     HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
     HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
     HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */
 
     /* Round 4 */
     II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
     II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
     II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
     II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
     II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
     II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
     II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
     II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
     II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
     II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
     II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
     II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
     II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
     II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
     II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
     II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
     state[0] += a;
     state[1] += b;
     state[2] += c;
     state[3] += d;
}
 
int md5(unsigned char encrypt[])
{
	int i;
//	unsigned char encrypt[] ="admin";//21232f297a57a5a743894a0e4a801fc3
	unsigned char decrypt[16];
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5,encrypt,strlen((char *)encrypt));
	MD5Final(&md5,decrypt);
//	printf("Before encryption:%s\nAfter encryption:",encrypt);
	for(i=0;i<16;i++){
		printf("%02x",decrypt[i]);
	}
 
	return 0;
}
 

#define MAX 60

char hill(char text[],char result[])
{
    int K1[2][2] = {{2,11},{9,7}}, K2[2][2] = {0};
    int Temp1[2] = {0}, Temp2[2] = {0};
    int T1[MAX] = {0}, T2[MAX] = {0};
    int len, flag=0, temp, temp1, i, j, num=0;

	num=1;
	
    if(num == 1){
        /**加密**/
        len = strlen(text);
        // 当长度为奇数时补齐一位
        if(len % 2 == 1)
        {
            text[len] = 'a';
            len = strlen(text);
            flag = 1;
        }
        // 将大写转成小写，并赋值给T1数组
        for(i=0; i<len; i++)
        {
            if(text[i] >= 'A' && text[i] <= 'Z')
            {
                text[i] = text[i] + 32;
            }

            T1[i] = text[i] - 'a';
        }
        // 得到加密后结果，存储在T2中
        for(i=0; i<len; i+=2)
        {
            Temp1[0] = T1[i];
            Temp1[1] = T1[i + 1];
            // Temp2存储密文int值
            Temp2[0] = (Temp1[0] * K1[0][0] + Temp1[1] * K1[1][0]) % 26;
            Temp2[1] = (Temp1[0] * K1[0][1] + Temp1[1] * K1[1][1]) % 26;
            T2[i] = Temp2[0];
            T2[i + 1] = Temp2[1];
        }
        if(flag == 1)
        {
            len = len - 1;
        }
        for(i=0; i<len; i++)
        {
            result[i] = T2[i] + 'a';
        }

    }

    return 0;
}





int main()
{

	printf("Please input your flag:\n");
		
	int i;
	char text[MAX] = {0};
	//对输入的处理 
    scanf("%[^\n]",text);
//	printf("%d\n",strlen(text));
	
	if(strlen(text)!=33)
	{
		printf("baka!!!!\n");
		system("pause");
		return 0;
	}
	
	
	char v1[]="JNCTF{WA_HO_great",v2[]="_but_need_more.}",v3[]="stillneedshy";
	
	char c1[]="JNCTF{WA_HO_great";
	
	
	//存储前半段
	 for(i=0;i<17;i++)v1[i] = text[i];
	 //存储并处理后半段 
	for(;i<33;i++)v2[i-17] = text[i];
	

	int d1,d2;
	d1 = v2[3];
	d2 = v2[6];
	
	int a = '_';
	
	if(d1!=a||d2!=a||v2[15]!='}'||v2[14]!='!')
	{
		printf("maybe better than baka!!!!\n");
		system("pause");
		return 0;
	}
	else
	{
		int j=0;
		for(i=0;i<16;i++)
		{
			if(v2[i]==a||v2[i]=='}'||v2[i]=='!');
			else if(v2[i]=='1')v3[j++] = 'i';
			else if(v2[i]=='0')v3[j++] = 'o';
			else if(v2[i]=='5')v3[j++] = 's';
			else v3[j++] = v2[i]; 
		}
	
		
	}	
	
	//17 16 12                        
	char v4[MAX] = {0};

//前半段： 
	rc4(v1);
	
	FILE *fp;
/*	
	fp = fopen("flag","w");
	fprintf(fp,"%s\n",v1);
	fclose(fp); 
*/	

	strcpy(junk,v1);
	unk_40011E();//此时flag为rc4加密后的内容
	

//后半段
 	hill(v3,v4);//希尔加密 

	
//验证
	fp = fopen("flag","r"); 
	fscanf(fp,"%s",c1);
	fclose(fp); 
	
	
	if(strcmp(flag,c1)==0)
	{
		if(strcmp(v4,trash)==0)
		{
			printf("you are not a rookie!!!\n");
			system("pause");
			return 0;
		}
		else
		{
			printf("just a little error,come on!!!\n");
			system("pause");
			return 0;
		}
		
	}
	
	return 0;
	
}
