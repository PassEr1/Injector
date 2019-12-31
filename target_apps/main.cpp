
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>




  #include <stdlib.h>


using namespace std;

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		cout << "pleae enter a file to monitor \n";	
	}
	else
	{
		cout << "here is the files content: \n";
		while(true)
		{
			ifstream fileToRead(argv[1]);
			if(fileToRead.good())
			{
				string line;
				while (std::getline(fileToRead, line))
				{
					cout << line << endl;
				}
				fileToRead.close();
				usleep(1000);
				system("clear");
			}
			
		}
		cout << endl;	
	}
	
}
