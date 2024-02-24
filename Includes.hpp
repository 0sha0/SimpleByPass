#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <comdef.h>
#include <wincred.h>
#include <fstream>
#include <list>
#include <detours/detours.h>
using namespace std;
#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR")//¼õĞ¡±àÒëÌå»ı
