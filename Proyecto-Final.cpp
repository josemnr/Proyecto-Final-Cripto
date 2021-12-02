// Proyecto-Final.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <string>

using namespace std;

void FileSigning() {
	cout << "\nYou are in op 4\n\n";
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
			break;
		case 2:
			cout << "\nYou are in op 2\n\n";
			break;
		case 3:
			cout << "\nYou are in op 3\n\n";
			break;
		case 4:
			FileSigning();
			break;
		case 5:
			cout << "\nYou are in op 5\n\n";
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
