#pragma once
class MAC
{
private:
	void printBlock(int block[][4], std::string phase);
	void generateSubkeys(int[16]);
	int* shiftLeft(int[][4]);
	void initValues();

	int K1[4][4];
	int K2[4][4];


public:
	MAC(int);

	void generateCMAC(int[], std::string);
	bool verifyCMAC(int[], std::string, int[]);

	int CMAC[16];

};

