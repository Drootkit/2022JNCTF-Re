#include <stdio.h>
#include <windows.h>

typedef int(* my_func)();

int main(void)
{ 
    HINSTANCE dllA; my_func f1;
    dllA = LoadLibrary("Ohhscvhost.dll"); 
    if(NULL==dllA)  
    printf("�޷�����dll!\n"); 
    f1 = (my_func)GetProcAddress(dllA,"Ordinal2"); 
    if(NULL==f1)  
        printf("�Ҳ���������ַ��\n");
    f1(); 
    //printf("���ý����%d\n", f1());

    return 0;
 }
