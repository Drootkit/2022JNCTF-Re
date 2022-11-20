#include <stdio.h>
#include <windows.h>

typedef int(* my_func)();

int main(void)
{ 
    HINSTANCE dllA; my_func f1;
    dllA = LoadLibrary("Ohhscvhost.dll"); 
    if(NULL==dllA)  
    printf("无法加载dll!\n"); 
    f1 = (my_func)GetProcAddress(dllA,"Ordinal2"); 
    if(NULL==f1)  
        printf("找不到函数地址！\n");
    f1(); 
    //printf("调用结果：%d\n", f1());

    return 0;
 }
