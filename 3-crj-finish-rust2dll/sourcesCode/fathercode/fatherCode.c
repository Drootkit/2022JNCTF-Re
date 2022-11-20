// gcc --share dll.c -o dll.dll

#include<stdlib.h>
#include<stdio.h>
#include<windows.h>
#include<string.h>

#include "dll.h"	//优先在当前目录寻找

#define size 256

//生成请输入用户名
char* input_name()
{
	char *name = (char*)malloc(32);
	int arr[] = {98, 68, 69, 89, 86, 90, 82, 13, 23};
	int i;
	for(i=0; i<sizeof(arr)/sizeof(int); i++)
		name[i] = (char)arr[i] ^ 0x37;
	name[i] = '\0';
	return name;
}

//生成请输入验证码
char* input_code()
{
	char *name = (char*)malloc(32);
	int arr[] = {101, 82, 80, 94, 68, 67, 69, 86, 67, 94, 88, 89, 23, 116, 88, 83, 82, 13, 23};
	int i;
	
	for(i=0; i<sizeof(arr)/sizeof(int); i++)
		name[i] = (char)arr[i] ^ 0x37;
	name[i] = '\0';
	
	return name;
}

//感谢你购买我的产品
char* output_sucess()
{
	char *name = (char*)malloc(128);
	int arr[] = {153, 165, 172, 163, 166, 237, 180, 162, 184, 237, 171, 162, 191, 237, 189, 184, 191, 174, 165, 172, 190, 164, 163, 170, 237, 162, 184, 191, 237, 189, 191, 162, 169, 184, 174, 185, 190};
	int i;
	
	for(i=0; i<sizeof(arr)/sizeof(int); i++)
		name[i] = (char)arr[i] ^ 0xcd;
	name[i] = '\0';
	
	return name;
}

//输入的验证码是错误的
char* output_error()
{
	char *name = (char*)malloc(48);
	int arr[] = {71, 98, 127, 126, 119, 48, 98, 117, 119, 121, 99, 100, 98, 113, 100, 121, 127, 126, 48, 115, 127, 116, 117, 48, 127, 98, 48, 69, 99, 98, 126, 113, 125, 117};
	int i;
	
	for(i=0; i<sizeof(arr)/sizeof(int); i++)
		name[i] = (char)arr[i] ^ 0x10;
	name[i] = '\0';
	
	return name;
}

//计算长度
int StrLen(char *name)
{
	int i=0;
	for(i=0; *(name+i) != '\0';i++);
	return i;
}

//根据输入的a参数，判断加密中的细小的加密算法
//https://blog.csdn.net/qq_44310495/article/details/109388497
int TLSCallback_2(int seed)
{
	unsigned char key[100]={0};
	unsigned char data[100]={0};
	int arr[] = { 0x68, 0x4c, 0x55, 0x43, 0x62, 0xb, 0x62, 0x62};
	int i = 0;
	unsigned int sum;

	unsigned char sbox[257]={0};
	
	for(i=0;i<14;i++)
		key[i] = ((((i+0x44)^0x92+0x4D)^0x21)<<i)%127;

	for(i=0;i<8;i++)
		data[i] = arr[i]^0x22;
	
	/*enc_dec*/
	int j,k,R,tmp;
	
		/*循环初始化key*/
	for(j=0;j<strlen(key);j++)
	{
		unsigned int i,j,k;
		int tmp;
		
		//初始化的s表
		for(i=0;i<size;i++)
			sbox[i]=i+((i+34)>>i)+i%32;//初始化s表的时候进行复杂化
		
		j=k=0;
		
		//用key来实例化s表
		for(i=0;i<size;i++)
		{
			tmp = sbox[i]^10;
			
			j=(j+(tmp>>1)+key[strlen((char*)key) - k])%size;
			
			sbox[i] = sbox[j]+0x90;
			
			sbox[j] = tmp - 0xe8;
			
			if(++k>=strlen((char*)key))k=0;
		}
	}
		/*init_key end*/	
	j=k=0;	
	for(i=0;i<strlen((char*)data);i++)
	{
		j=((j+1)>>3)%size;
		k=(k+sbox[(j^(i+3))%strlen((char*)data)])%size;
		
		tmp=sbox[j];
		sbox[j]=sbox[k];
		sbox[k]=tmp;
		
		R=((sbox[(sbox[j]+sbox[k])%size]^0xE852)+0xcc)^0x18a;
		
		data[i]^=R;
	}
	/*enc_end*/
	
	for(i=0;i<strlen((char*)data);i++)
		sum += data[i]^seed;
/*
	code判断的时候进行的正确答案的比较数字【前面是参数，后面是对应的答案】
	0x11223344  0x89119c08
	0xedfac873	0x6fd64390
	0xaecfed81	0x767f6c8c
*/
	return sum;
}

//判断名称是否正确
int name_AreUsure(long long* arr)
{
	int i=0;
//	for(i=0;i<3;i++)
//		printf("-- %llx\n", arr[i]);
	/*
		x	0xd3561788	3545634696
		y	0xa6acc5bd	2796340669
		z	0x2ba6f5fb	732362235
	*/
	
	//通过一个三元一次方程组来判断是否正确, 正确返回1，否则返回0
	if(
		9721*arr[0]+8975*arr[1]-921*arr[2] == 58889766765656 &&
		3353*arr[1]-88*arr[2]-967*arr[0] == 5883053635445 &&
		9812*arr[2]-arr[0]+314*arr[1] == 8060443585190
	)
		return 1;
	else
		return 0;

}

//num是一个种子a，种子就是当前片段的长度,生成16进制数字, 生成最大值和最小值中间的数字
long long CreateHex(int num, long long min, long long max)
{
//	printf("%ld\n", sizeof(long long));
	srand(num);
	return rand()%(max + 1 - min) + min;
}

//操作名称并进行验证
float name_FindSpecificCharacters(char *str)
{
	/*Mand-Iant-Jnse*/
	int i;
	float flag = 0;
	int flag1 = 0;
	int j = 0;
	char first = 0;
	int sum = 0;
	char *name = (char*)malloc(strlen(str)*sizeof(char)+2);
	char *part;
	char *tmp;
	char* hex = (char*)malloc(32*sizeof(char));
	char *no_use;
	long long res_test[10] = {0};
	
	sprintf(name, "%s", str);
	
	//判断-后面开头是否大写
	for(i=0;i<strlen(name);i++)
	{
		if(name[i] == '-')
		{
			flag1++;
			flag += 0.5;
			if(name[i+1] <= 'Z' && name[i+1] >= 'A')
				flag += 0.5;
		}
	}
	j=0;
	
	//判断横杠的个数是2，否则退出
	if(flag1-2!=0)
	{
//		printf("wrong\n"); 
		return 0;
	}
	
	//得到分割开的第一个字符串
	part = strtok(name, "-");
	
	//将每-链接的部分分开
	while( part != NULL )
	{
		for(i=0;i<strlen(part);i++)
			sprintf((char*)(hex + i*2), "%02X", part[i]);//首先将字符串转换为16进制的字符串形式。
		long long test = strtol(hex, &no_use, 16);//将16进制的字符串转换成10进制长整型数字。
		j+=1;
		/*
			0xd3561788
			0xa6acc5bd
			0x2ba6f5fb
		*/
		switch(j)
		{
			case 1:
				test ^= CreateHex(0x4, 0x9E3779B9, 0xffffffff);
//				printf("case 1: %llx\n", test);
				break;
			case 2:
				test ^= CreateHex(0x8, 0xefcdab89, 0xffffffff);
//				printf("case 2: %llx\n", test);
				break;
			case 3:
				test ^= CreateHex(0xf, 0x61C88647, 0xffffffff);
//				printf("case 3: %llx\n", test);
				break;
		}
		res_test[j-1] = test;//将每段名称的返回值存到数组里
	    part = strtok(NULL, "-");
    }
    
//    for(i=0;i<4;i++)
//    	printf("0x%llx\n", res_test[i]);
    
    if(!name_AreUsure(res_test))
    	return 0;
    
	return flag;
}

//encode验证码并进行验证
float code_FindSpecificCharacters(char *str)
{
	/*9n5e_1#St_7@nG*/
	float flag = 0;
	int flag1 = 0;
	char first = 0;
	int sum = 0;
	int j = 0;
	int i;
	char *code = (char*)malloc(strlen(str)*sizeof(char)+2);
	char *part;
	char *tmp;
	char* hex = (char*)malloc(32*sizeof(char));
	char *no_use;
	long long res_cmp[4] = {0x89119c08, 0x6fd64390, 0x767f6c8c};
	
	sprintf(code, "%s", str);
	
	//判断_后面开头是否是数字
	for(i=0;i<strlen(code);i++)
	{
		if(code[i] == '_')
		{
			flag1++;
			flag += 0.5;
			if(code[i+1] <= '0' && code[i+1] >= '9')
				flag += 0.5;
		}
	}
	//判断_的个数是2，否则退出
	if(flag1-2!=0)
	{
//		printf("wrong\n"); 
		return 0;
	}
	
	//得到分割开的第一个字符串
	part = strtok(code, "_");
	
	//将每-链接的部分分开成每一个part，并装换成一串16进制数字
	j=0;
	while( part != NULL )
	{
//		计算每一部分的长度
		if(StrLen(part) != 4)
			return 0;

		for(i=0;i<strlen(part);i++)
			sprintf((char*)(hex + i*2), "%02X", part[i]);	//首先将字符串转换为16进制的字符串形式。
		long long test = strtol(hex, &no_use, 16);			//将16进制的字符串转换成10进制长整型数字。
		
		switch(j)
		{
			case 0:
				test ^= TLSCallback_2(0x11223344);
				break;
			case 1:
				test ^= TLSCallback_2(0xedfac873);
				break;
			case 2:
				test ^= TLSCallback_2(0xaecfed81);
				break;
		}
		printf("test = %lx\n", test);
		if(test == res_cmp[j])
			first++;
		else
			return 0;
//		first 最后等于 3
	    part = strtok(NULL, "_");
	    j+=1;
    }
	return (int)flag + first;
}

EXPORT void DllMainEntry()
{
	char name[48];
	char code[48];
	float res1 = 0;
	float res2 = 0;
	
//	printf("Usrname: \n");
	puts(input_name());
	scanf("%s", name);
	res1 = name_FindSpecificCharacters(name);
	
//	printf("Registration Code: \n");
	puts(input_code());
	scanf("%s", code);
	res2 = code_FindSpecificCharacters(code);
	
	if((int)(res1+res2) == 4)
		puts(output_sucess());
//		printf("Thank you for purchasing our products");
	else
		puts(output_error());
//		printf("The wrong registration code");

}





