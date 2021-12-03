// Proyecto-Final.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <string>
#include <iostream>
#include <stdlib.h>

//libsodium
#include "sodium.h"
#include <fstream>
#include <cstring>
#include <iomanip>
#define MESSAGE_LEN 4
#define CHUNK_SIZE 4096
#define MESSAGE (const unsigned char *) "test"

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

static int encryptFile(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {

		string fileToEncryptPath;
		string EncryptFilePath;

		cout << "\nIngresa la ruta del archivo a encriptar:"; // ./archivos/plain_text.txt
		cin >> fileToEncryptPath;

		cout << "\nIngresa la ruta destino del archivo encriptado:"; // ./archivos/encryptedFile
		cin >> EncryptFilePath;

		unsigned char  buf_in[CHUNK_SIZE];
		unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
		unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
		crypto_secretstream_xchacha20poly1305_state st;
		FILE* fp_t, * fp_s;
		unsigned long long out_len;
		size_t         rlen;
		int            eof;
		unsigned char  tag;
		fp_s = fopen(fileToEncryptPath.c_str(), "rb");
		fp_t = fopen(EncryptFilePath.c_str(), "wb");
		crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
		fwrite(header, 1, sizeof header, fp_t);
		do {
			rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
			eof = feof(fp_s);
			tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
			crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
				NULL, 0, tag);
			fwrite(buf_out, 1, (size_t)out_len, fp_t);
		} while (!eof);
		fclose(fp_t);
		fclose(fp_s);
		return 0;
}


static int
decryptFile(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
	string fileToDecryptPath;
	string DecryptFilePath;

	cout << "\nIngresa la ruta del archivo a desencriptar:"; // ./archivos/encryptedFile
	cin >> fileToDecryptPath;

	cout << "\nIngresa la ruta destino del archivo desencriptado:"; // ./archivos/decryptedFile
	cin >> DecryptFilePath;

	unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char  buf_out[CHUNK_SIZE];
	unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE* fp_t, * fp_s;
	unsigned long long out_len;
	size_t         rlen;
	int            eof;
	int            ret = -1;
	unsigned char  tag;
	fp_s = fopen(fileToDecryptPath.c_str(), "rb");
	fp_t = fopen(DecryptFilePath.c_str(), "wb");
	fread(header, 1, sizeof header, fp_s);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
		goto ret; // incomplete header 
	}
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
			buf_in, rlen, NULL, 0) != 0) {
			goto ret; // corrupted chunk
		}
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
			goto ret; // premature end (end of file reached before the end of the stream) 
		}
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);
	ret = 0;
ret:
	fclose(fp_t);
	fclose(fp_s);
	return ret;
}


void fileSigning() {
	// Load the private key from an PEM file:
	CkPrivateKey pkey;
	string privateKeyPath;
	cout << "\nIngresa la ruta de tu llave privada:"; // ./llaves/private_key.pem
	cin >> privateKeyPath;
	bool success = pkey.LoadPemFile(privateKeyPath.c_str());
	if (success != true) {
		cout << pkey.lastErrorText() << "\r\n" << flush;
		return;
	}

	// Import the private key into the RSA component:
	CkRsa rsa;
	success = rsa.ImportPrivateKeyObj(pkey);
	if (success != true) {
		cout << rsa.lastErrorText() << "\r\n" << flush;
		return;
	}

	// OpenSSL uses big-endian.
	rsa.put_LittleEndian(false);

	// Load the file to be signed.
	CkBinData bdFileData;
	string plainTextPath;
	cout << "\nIngresa la ruta del texto a firmar:"; // ./archivos/plain_text.txt
	cin >> plainTextPath;
	success = bdFileData.LoadFile(plainTextPath.c_str());

	CkBinData bdSig;
	success = rsa.SignBd(bdFileData, "sha1", bdSig);
	if (success != true) {
		cout << rsa.lastErrorText() << "\r\n" << flush;
		return;
	}

	// Save the binary signature to a file.
	string binarySignaturePath;
	cout << "\nIngresa la ruta destino de la firma binaria:"; // ./llaves/bin_key.txt
	cin >> binarySignaturePath;
	success = bdSig.WriteFile(binarySignaturePath.c_str());
	if (success != true) {
		cout << "\nError al crear firma binaria" << "\r\n\n" << flush;
		return;
	}
	cout << "\nLa firma binaria fue creada con exito." << "\r\n\n" << flush;
}

void verifySignature() {
	CkPublicKey pubKey;
	string publicKeyPath;

	// Load the public key from an PEM file:
	cout << "\nIngresa la ruta de tu llave publica:"; // ./llaves/public_key.pem
	cin >> publicKeyPath;
	bool success = pubKey.LoadOpenSslPemFile(publicKeyPath.c_str());
	if (success != true) {
		cout << pubKey.lastErrorText() << "\r\n" << flush;
		return;
	}

	// Load the data of the original file that was signed.
	CkBinData bdFileData;
	string plainTextPath;
	cout << "\nIngresa la ruta del texto firmado:"; // ./archivos/plain_text.txt
	cin >> plainTextPath;
	success = bdFileData.LoadFile(plainTextPath.c_str());

	// Load the signature.
	CkBinData bdSig;
	string binarySignaturePath;
	cout << "\nIngresa la ruta de la firma binaria:"; // ./llaves/bin_key.txt
	cin >> binarySignaturePath;
	success = bdSig.LoadFile(binarySignaturePath.c_str());

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
		cout << "\nFirma invalida" << "\r\n\n" << flush;
		return;
	}

	cout << "\nFirma verificada." << "\r\n\n" << flush;
}

void Menu() {

	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	crypto_secretstream_xchacha20poly1305_keygen(key);

	int choice;
	do {
		cout << "Selecciona una opcion valida del menu:\n";
		cout << "1. Generacion y Recuperacion de Claves desde 1 archivo\n2. Cifrado de Archivos\n3. Descifrado de Archivos\n4. Firma de Archivos\n5. Verificacion de Firma de Archivos\n6. Salir\n\n";
		cin >> choice;
		switch (choice) {
		case 1:
			cout << "\nYou in op 1\n\n";
			system("PAUSE");
			system("CLS");
			break;
		case 2:
			if (encryptFile(key) != 0) {
				cout << "\nError al encriptar el archivo\n\n" << flush;
			}
			else {
				cout << "\nArchivo encriptado con exito\n\n" << flush;
			}
			system("PAUSE");
			system("CLS");
			break;
		case 3:
			if (decryptFile(key) != 0) {
				cout << "\nError al desencriptar el archivo\n\n" << flush;
			}
			else {
				cout << "\nArchivo desencriptado con exito\n\n" << flush;
			}
			system("PAUSE");
			system("CLS");
			break;
		case 4:
			fileSigning();
			system("PAUSE");
			system("CLS");
			break;
		case 5:
			verifySignature();
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

	if (sodium_init() < 0) {
		return -1;
	}

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
