#include <sample.h>

int Factorial(int n)
{
  int result = 1;
  for (int i=1; i<=n; i++)
  {
    result *= i;
  }
  return result;
}

//int main()
//{
//  return 0;
//}
