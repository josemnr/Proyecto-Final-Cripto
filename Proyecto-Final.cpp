// Proyecto-Final.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <stdlib.h>
#include <string>

//libraries related to signatures
#include <CkRsa.h>
#include <CkBinData.h>

//libraries to signing files
#include <CkPrivateKey.h>

//libraries to verify signature
#include <CkGlobal.h>
#include <CkPublicKey.h>

using namespace std;

/*
void ChilkatSample(void)
{
	// The Chilkat API can be unlocked for a fully-functional 30-day trial by passing any
	// string to the UnlockBundle method.  A program can unlock once at the start. Once unlocked,
	// all subsequently instantiated objects are created in the unlocked state. 
	// 
	// After licensing Chilkat, replace the "Anything for 30-day trial" with the purchased unlock code.
	// To verify the purchased unlock code was recognized, examine the contents of the LastErrorText
	// property after unlocking.  For example:
	CkGlobal glob;
	bool success = glob.UnlockBundle("Anything for 30-day trial");
	if (success != true) {
		cout << glob.lastErrorText() << "\r\n";
		return;
	}

	int status = glob.get_UnlockStatus();
	if (status == 2) {
		cout << "Unlocked using purchased unlock code." << "\r\n";
	}
	else {
		cout << "Unlocked in trial mode." << "\r\n";
	}

	// The LastErrorText can be examined in the success case to see if it was unlocked in
	// trial more, or with a purchased unlock code.
	cout << glob.lastErrorText() << "\r\n";
}*/

void FileSigning() {
	cout << "\nYou are in op 4\n\n";
	CkPrivateKey pkey;

	// Load the private key from an PEM file:
	bool success = pkey.LoadPemFile("D:/ITESO/Cripto/Proyecto-Final/llaves/private_key.pem");
	if (success != true) {
		std::cout << pkey.lastErrorText() << "\r\n";
		return;
	}

	CkRsa rsa;

	// Import the private key into the RSA component:
	success = rsa.ImportPrivateKeyObj(pkey);
	if (success != true) {
		std::cout << rsa.lastErrorText() << "\r\n";
		return;
	}

	// OpenSSL uses big-endian.
	rsa.put_LittleEndian(false);

	// Load the file to be signed.
	CkBinData bdFileData;
	success = bdFileData.LoadFile("D:/ITESO/Cripto/Proyecto-Final/llaves/plain_text.txt");

	CkBinData bdSig;
	success = rsa.SignBd(bdFileData, "sha1", bdSig);
	if (success != true) {
		cout << rsa.lastErrorText() << "\r\n";
		return;
	}

	// Save the binary signature to a file.
	success = bdSig.WriteFile("D:/ITESO/Cripto/Proyecto-Final/llaves/binary.txt");
	if (success != true) {
		cout << "Failed to write signature.sig." << "\r\n";
		return;
	}

	cout << "Success." << "\r\n";

}

void VerifySignature() {
	cout << "\nYou are in op 5\n\n";

	CkPublicKey pubKey;

	// Load the public key from an PEM file:
	bool success = pubKey.LoadOpenSslPemFile("D:/ITESO/Cripto/Proyecto-Final/llaves/public_key.pem");
	if (success != true) {
		cout << pubKey.lastErrorText() << "\r\n" << flush;
		return;
	}

	// Load the data of the original file that was signed.
	CkBinData bdFileData;
	success = bdFileData.LoadFile("D:/ITESO/Cripto/Proyecto-Final/llaves/plain_text.txt");

	// Load the signature.
	CkBinData bdSig;
	success = bdSig.LoadFile("D:/ITESO/Cripto/Proyecto-Final/llaves/firma_binaria.txt");

	CkRsa rsa;

	// Import the public key into the RSA component:
	success = rsa.ImportPublicKeyObj(pubKey);
	if (success != true) {
		cout << rsa.lastErrorText() << "\r\n" << flush;
		return;
	}

	// OpenSSL uses big-endian.
	rsa.put_LittleEndian(false);

	success = rsa.VerifyBd(bdFileData, "sha1", bdSig);
	if (success != true) {
		cout << "The signature was invalid." << "\r\n\n" << flush;
		return;
	}

	cout << "The signature was verified." << "\r\n\n" << flush;
}

void Menu() {
	int choice;
	do {
		cout << "Selecciona una opcion valida del menu:\n";
		cout << "1. Generacion y Recuperacion de Claves desde 1 archivo\n2. Cifrado de Archivos\n3. Descifrado de Archivos\n4. Firma de Archivos\n5. Verificacion de Firma de Archivos\n6. Salir\n";
		cin >> choice;
		switch (choice) {
		case 1:
			cout << "\nYou in op 1\n\n";
			system("PAUSE");
			system("CLS");
			break;
		case 2:
			cout << "\nYou are in op 2\n\n";
			system("PAUSE");
			system("CLS");
			break;
		case 3:
			cout << "\nYou are in op 3\n\n";
			system("PAUSE");
			system("CLS");
			break;
		case 4:
			FileSigning();
			break;
		case 5:
			VerifySignature();
			system("PAUSE");
			system("CLS");
			break;
		case 6:
			cout << "\nOk, bye\n\n";
			break;
		default:
			cout << "\nSelecciona una opcion valida\n\n";
			break;
		}
	} while (choice != 6);
}

int main() {
	Menu();
}



// Ejecutar programa: Ctrl + F5 o menú Depurar > Iniciar sin depurar
// Depurar programa: F5 o menú Depurar > Iniciar depuración

// Sugerencias para primeros pasos: 1. Use la ventana del Explorador de soluciones para agregar y administrar archivos
//   2. Use la ventana de Team Explorer para conectar con el control de código fuente
//   3. Use la ventana de salida para ver la salida de compilación y otros mensajes
//   4. Use la ventana Lista de errores para ver los errores
//   5. Vaya a Proyecto > Agregar nuevo elemento para crear nuevos archivos de código, o a Proyecto > Agregar elemento existente para agregar archivos de código existentes al proyecto
//   6. En el futuro, para volver a abrir este proyecto, vaya a Archivo > Abrir > Proyecto y seleccione el archivo .sln
