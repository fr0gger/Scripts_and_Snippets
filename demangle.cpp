#include <iostream>

using namespace std;

void add(int a, int b){cout << a + b << endl;}
void add(double a, double b){cout << a + b << endl;}

int main()
{
    add(1, 2);
    add(5.5, 8.3);
    cout << "Hello world!" << endl;
    return 0;
}
