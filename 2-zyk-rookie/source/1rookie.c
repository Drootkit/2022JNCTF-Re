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
}RC4_INFO,*PRC4_INFO;			//���� RC4 ��Ҫ�õ��� S-Box ����ʱ���� T����װ�ڽṹ���в�������������ָ������� 
 
void rc4_init(PRC4_INFO prc4,unsigned char key[],unsigned int keylen)
{
	int i=0;
	int j=0;
	unsigned char tmp;
	if(prc4==NULL)return;
	/*
	��ʼ���洢0-255�ֽڵ�Sbox(��ʵ����һ������)
	���key��256���ֽ������г�ΪTbox(�������key����256���ֽ����ʼ����256���ֽ�)
	*/ 
	for(i=0;i<256;i++)
	{
		prc4->s_box[i] = i;
		prc4->t_box[i] = key[i % keylen];	//�����Կ�ĳ�����256�ֽڣ���ֱ�Ӱ���Կ��ֵ����k��������ת�ؽ���Կ��ÿ���ֽڸ���k 
	}
	
	//����s[i]��s[j]   i ��0��ʼһֱ��255�±����. j�� s[i]��T[i]��ϵó����±�
	for(i=0;i<256;i++)
	{
		j=(j+prc4->s_box[i]+prc4->t_box[i])%256;
		//��ʼ����
		tmp=prc4->s_box[i];
		prc4->s_box[i]=prc4->s_box[j];
		prc4->s_box[j]=tmp;
	}
}

void rc4_crypt(unsigned char data[],unsigned int datalen,unsigned char key[],unsigned int keylen)	//�����ֱ���Ҫ���ܵ����ݡ�Ҫ���ܵ����ݳ��ȡ������������õ�Key�������������õ�key����
{
	int dn=0;	//data[n]����˼
	int i=0;
	int j=0;	//i j�ֱ����ڽ���sbox[i] �� sbox[j]
	int t=0;	//t = s[i] +s[j]
	unsigned char tmp;
	
	RC4_INFO rc4;		//���ﶨ��ǰ��Ľṹ�� 
	rc4_init(&rc4,key,keylen);		//�ڼ��ܺ����е��ó�ʼ����������ʡȥ�����������г��ֵ�Ҫ�����ʼ�� sBox ��������.
	
	for(dn=0;dn<datalen;dn++)
	{
		//iȷ��S-box��ÿ��Ԫ�ض��õ�����j��֤S-box�Ľ���������ġ�
		i=(i+1)%256;
		j=(j+rc4.s_box[i])%256;
		
		//���� s_box[i] �� s_box[j]
		tmp=rc4.s_box[i];
		rc4.s_box[i] = rc4.s_box[j];
		rc4.s_box[j] = tmp;
		
		//������֮�� �ٰ�s[i] + s[j]����ϵ����±���ȥ���.
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
    EntryBuffer((unsigned char*)Hell,17); //�ӵ�һ�ε��þ��Ǽ��� 
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
        /**����**/
        len = strlen(text);
        // ������Ϊ����ʱ����һλ
        if(len % 2 == 1)
        {
            text[len] = 'a';
            len = strlen(text);
            flag = 1;
        }
        // ����дת��Сд������ֵ��T1����
        for(i=0; i<len; i++)
        {
            if(text[i] >= 'A' && text[i] <= 'Z')
            {
                text[i] = text[i] + 32;
            }

            T1[i] = text[i] - 'a';
        }
        // �õ����ܺ������洢��T2��
        for(i=0; i<len; i+=2)
        {
            Temp1[0] = T1[i];
            Temp1[1] = T1[i + 1];
            // Temp2�洢����intֵ
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
	//������Ĵ��� 
    scanf("%[^\n]",text);

	if(strlen(text)!=33)
	{
		printf("baka!!!!\n");
		system("pause");
		return 0;
	}

	char v1[]="JNCTF{WA_HO_great",v2[]="_but_need_more.}",v3[]="stillneedshy";

	char c1[]="JNCTF{WA_HO_great";
	
	//�洢ǰ���
	 for(i=0;i<17;i++)v1[i] = text[i];
	 //�洢��������� 
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

    //ǰ��Σ� 
	rc4(v1);

	FILE *fp;
	strcpy(junk,v1);
	unk_40011E();//��ʱflagΪrc4���ܺ������

    //����
 	hill(v3,v4);//ϣ������ 

    //��֤
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