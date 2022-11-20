# rookie

思路：

简单逆向，对输入进行加密，与原本的存储进行对比。

1. 判断输入长度
2. 对前半段rc4加密
3. 对后半段希尔加密
4. 对后半段中间有对符号和数字的判断

脚本：

1.先对rc4部分

```
#include<stdio.h>
#include <stdint.h>  
#include<string.h>
#include <stdlib.h>
#include <memory.h>

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

int main()
{
	unsigned char c1[]="JNCTF{foR_THe_r0O";
	
	FILE *fp;
	fp = fopen("flag","r"); 
	fscanf(fp,"%s",c1);
	fclose(fp); 
	
	EntryBuffer(c1,17);
	printf("%s\n",c1);
	
 } 
```

得到：JNCTF{foR_THe_r0O

2.再对希尔密码部分

```
#include <stdio.h>
#include <string.h>

#define MAX 60

int main()
{
    int K1[2][2] = {{2,11},{9,7}}, K2[2][2] = {0};
    int Temp1[2] = {0}, Temp2[2] = {0};
    char text[MAX] = "okxvznpjfhus",result[MAX] = {0};
    int T1[MAX] = {0}, T2[MAX] = {0};
    int len, flag=0, temp, temp1, i, j;

        /**解密**/
        len = strlen(text);
        // 当长度为奇数时补齐一位
        if(len % 2 == 1)
        {
            text[len] = 'a';
            len = strlen(text);
            flag = 1;
        }
        for(i=0; i<len; i++)
        {
            if(text[i] >= 'A' && text[i] <= 'Z')
            {
                text[i] = text[i] + 32;
            }
            T2[i] = text[i] - 'a';
        }
        // 求K的逆
        temp = -1;
        for(i=1; temp < 0; i++)
        {
            temp = (K1[0][0] * K1[1][1] - K1[0][1] * K1[1][0]) + 26 * i;
        }
        i = 1;
        while(1)
        {
            if((temp * i) % 26 == 1)
            {
                temp1 = i;
                break;
            }
            else
            {
                i++;
            }
        }
        K2[0][0] = K1[1][1] * temp1;
        K2[0][1] = (((-1 * K1[0][1]) + 26) * temp1) % 26;
        K2[1][0] = (((-1 * K1[1][0]) + 26) * temp1) % 26;
        K2[1][1] = K1[0][0] * temp1;
        // 得到解密后结果，存储在T2中
        for(i=0; i<len; i+=2)
        {
            Temp2[0] = T2[i];
            Temp2[1] = T2[i + 1];
            // Temp1存储明文int值
            Temp1[0] = (Temp2[0] * K2[0][0] + Temp2[1] * K2[1][0]) % 26;
            Temp1[1] = (Temp2[0] * K2[0][1] + Temp2[1] * K2[1][1]) % 26;
            T1[i] = Temp1[0];
            T1[i + 1] = Temp1[1];
        }
        if(flag == 1)
        {
            len = len - 1;
        }
        for(i=0; i<len; i++)
        {
            result[i] = T1[i] + 'a';
        }
        printf("密文%s的明文为:%s\n",text,result);
    
    return 0;
}
```

得到：kietoreverse

最后更改为数字，插入符号，

得到flag：

`JNCTF{foR_THe_r0Ok1E_t0_REver5e!}`



