/*************************************************************************
	> File Name: target.c
	> Author: 
	> Mail: 
	> Created Time: 2017年12月05日 星期二 20时16分30秒
 ************************************************************************/


unsigned int target_function(unsigned int n){
    unsigned int mod = n % 4;
    unsigned int result = 0;

    if(mod == 0) result = (n | 0xBAAAD0BF) * (2 ^ n);

    else if(mod == 1) result = (n & 0xBAAAD0BF) * (3 + n);

    else if(mod == 2) result = (n ^ 0xBAAAD0BF) * (4 | n);

    else result = (n + 0xBAAAD0BF) * (5 & n);

    return result;
}
int main(){
    target_function(5);
}