#include <iostream>
using namespace std;

enum whisky { Glenmorangie, Dalmore, Penderyn, Macallan, Kavalan, Balvenie, Balblair};

int main()
{
    whisky wales;
    wales = Penderyn;
    cout << "Whisky " << wales << "\n";

    whisky lowland;
    lowland = Glenmorangie;
    cout << "Whisky " << lowland;

    return 0;
}