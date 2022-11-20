#include <stdlib.h>
#include<stdio.h>
#include<string.h>
#include <fcntl.h>

int s[] = {22, 0, 6, 2, 30, 24, 9, 1, 21, 7, 18, 10, 8, 12, 17, 23, 13, 4, 3, 14, 19, 11, 20, 16, 15, 5, 25, 36, 27, 28, 29, 37, 31, 32, 33, 26, 34, 35};

int input(int *a1)
{
	int i;
	for(i=0;i<38;i++)scanf("%c",&a1[i]);
	a1[38] = '\0';
	return 0;
}

int count(const char*a1,int *a2)
{
	char buf;
	int fd;
	fd = open(a1,0);
	while(read(fd,&buf,1uLL)==1)a2[buf]++;

	close(fd);
	return 0;
}

void c1(int *a1,int a2)
{
	int i,j;
	for(i=0;i<a2;i++)
	{
		for(j=0;j<38;j++)
		{
			if(i==s[j])
			{
				a1[i] = a1[j];
				i=j;
				break;
			}
			
		}
	}
}

void c2(char *a1,int a2)
{
	int i;

	for(i=0;i<a2-1;i++)a1[i]=(a1[i]<<3) | (a1[i+1]>>5);
	a1[i]=(a1[i]<<3) | (a1[0]>>5);
}


int c3(char *a1,const char *a2,int a3)
{
	int i;
	FILE* fd;
	char c;
	fd = fopen(a2,"a+");
	for(i=0;i<a3;i++)
	{
		c = a1[i];
		fputc(c,fd);
	}
	
	return fclose(fd);
}


int encrypt(int *a1,int *a2)
{
	int i;
	int v4=38;
	char v5[56];

	for(i=0;i<v4;i++)v5[i]=a2[a1[i]];

//	c1((int*)v5,v4);

	c2(v5,v4);

	c3(v5,"out",v4);
	return 0;
}
int main()
{
	int v4[0xff]={0};
	int v5[0x50]={0};
	int i;
	input(v5);
	count("star",v4);
	encrypt(v5,v4);
	return 0; 
	
} 


