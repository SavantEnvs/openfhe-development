#include "openfhe.h"
#include <iostream>
using namespace lbcrypto;
int main(){ BigInteger a("5555555555400055555555"), b("5555555555555555551170");
 std::cout<<"a/b="<<a/b<<"\na%b="<<a%b<<"\n(a/b)*b="<<(a/b)*b<<"\nsum="<<((a/b)*b+(a%b))<<"\n"<<a<<"\n";}
