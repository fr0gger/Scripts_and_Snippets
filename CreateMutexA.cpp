#include <iostream>
#include <Windows.h>

using namespace std;

int main()
{
    HANDLE hMutex;
    hMutex = CreateMutex (NULL,FALSE,"COUCOU");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
       return 0;

    cout << "Mutex Created" << endl;
    return 0;
}
