#include <stdio.h>  
#include <string.h>
#include <stdlib.h>

char junk[17]  = {0};
char flag[] = "JNCTF{WA_HO_great";

char trash[]="okxvznpjfhus";

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
	if(prc4==NULL)return;
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
    return 0;
}

void unk_40011E()
{
	strcpy(flag,junk);
}

#define MAX 60

char hill(char text[],char result[])
{
    int K1[2][2] = {{2,11},{9,7}}, K2[2][2] = {0};
    int Temp1[2] = {0}, Temp2[2] = {0};
    int T1[MAX] = {0}, T2[MAX] = {0};
    int len, flag=0, temp, temp1, i, j, num=1;
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