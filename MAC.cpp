#include <iostream>
#include <fstream>
#include <vector>

#include "MAC.h"
#include "AES.h"

const int const_Zero[4][4] = { {0x00, 0x00, 0x00, 0x00},
								{0x00, 0x00, 0x00, 0x00},
								{0x00, 0x00, 0x00, 0x00},
								{0x00, 0x00, 0x00, 0x00} };

const int const_Rb[4][4] = { {0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x00},
							{0x00, 0x00, 0x00, 0x87} };

const int const_Bsize = 16;

void MAC::printBlock(int block[][4], std::string phase) {
	std::cout << "---------------" << phase << "---------------" << std::endl;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			std::cout << std::hex << block[j][i];
		}
	}
	std::cout << std::endl;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			std::cout << std::hex << block[j][i] << " ";
		}
	}
	std::cout << std::endl;
}

int* MAC::shiftLeft(int block[][4]) {
	bool addOne = false;
	for (int i = 3; i >= 0; i--) {
		for (int j = 3; j >= 0; j--) {
			// Has a 1 at the front
			if (block[j][i] >= 0x80) {
				block[j][i] = block[j][i] << 1;
				block[j][i] = block[j][i] - 0xff - 0x01;
				if (addOne) block[j][i] += 0x01;
				addOne = true;
			}
			else {
				block[j][i] = block[j][i] << 1;
				if (addOne) block[j][i] += 0x01;
				addOne = false;
			}
		}
	}
	return 0;
}

void MAC::generateSubkeys(int key[16]) {
	
	AES enc(key, 10);
	int cipher[4][4];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			cipher[i][j] = const_Zero[i][j];
		}
	}
	enc.encryptBlock(cipher);
	
	//K1 generation
	if (cipher[0][0] < 0x80) {
		shiftLeft(cipher);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				K1[j][i] = cipher[j][i];
			}
		}
	}
	else {
		shiftLeft(cipher);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				K1[j][i] = cipher[j][i] ^ const_Rb[j][i];
			}
		}
	}
	// K2 generation
	if (K1[0][0] < 0x80) {
		shiftLeft(K1);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				K2[j][i] = K1[j][i];
			}
		}
	}
	else {
		shiftLeft(cipher);
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				K2[j][i] = cipher[j][i] ^ const_Rb[j][i];
			}
		}
	}
}

void MAC::generateCMAC(int key[], std::string inFile) {

	generateSubkeys(key);

    std::ifstream input;
    input.open(inFile);
    unsigned char byte = 0;
    std::vector <unsigned int> message;
    while (input >> std::noskipws >> byte) {
        message.push_back((int)byte);
    }
    input.close();

    int messageLen = message.size();
	int blocks = messageLen / const_Bsize;

	if (messageLen % const_Bsize != 0) blocks++;

	bool flag = false;

	if (blocks == 0) {
		blocks = 1;
		flag = false;
	} else {
		flag = messageLen % const_Bsize == 0 ? true : false;
	}

	int last_start = (blocks - 1) * const_Bsize;
	int M_last[4][4];

	if (flag) {
		for (int i = 0; i < const_Bsize; i++) {
			M_last[i % 4][i / 4] = message[last_start + i] ^ K1[i % 4][i / 4];
		}
	}
	else {
		int paddingReq = const_Bsize - messageLen % const_Bsize;
		message.push_back(0x80);
		for (int j = 1; j < paddingReq; j++) {
			message.push_back(0x00);
		}
		for (int i = 0; i < const_Bsize; i++) {
			M_last[i % 4][i / 4] = message[last_start + i] ^ K2[i % 4][i / 4];
		}
	}

	int X[4][4];
	int Y[4][4];

	for (int i = 0; i < const_Bsize; i++) {
		X[i % 4][i / 4] = const_Zero[i % 4][i / 4];
	}

	AES enc(key, 10);
	for (int i = 0; i < (blocks - 1); i++) {
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				Y[k][j] = X[k][j] ^ message[i * const_Bsize + (j * 4 + k)];
			}
		}
		enc.encryptBlock(Y);
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				X[j][k] = Y[j][k];
			}
		}

	}
	for (int i = 0; i < const_Bsize; i++) {
		Y[i % 4][i / 4] = X[i % 4][i / 4] ^ M_last[i % 4][i / 4];
	}

	enc.encryptBlock(Y);

	for (int i = 0; i < const_Bsize; i++) {
		CMAC[i] = Y[i % 4][i / 4];
	}
}

bool MAC::verifyCMAC(int hash[16], std::string inFile, int key[16]) {
	generateCMAC(key, inFile);
	for (int i = 0; i < const_Bsize; i++) {
		if (hash[i] != CMAC[i]) return false;
	}
	return true;
}

void MAC::initValues() {
	for (int i = 0; i < const_Bsize; i++) {
		CMAC[i] = 0x00;
	}
}

MAC::MAC(int placeholder) {
	initValues();
}

