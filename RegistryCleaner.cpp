/* Simon Giesen, Sensitec Mainz, 160625
   Registry Cleaner    */
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

class USBRegistryCleaner {
private:
    std::vector<std::string> registryPaths = {
        // USB-Geräte Geschichte
        "SYSTEM\\CurrentControlSet\\Enum\\USB",
        "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",

        // Mounted Devices (Laufwerksbuchstaben-Zuordnungen)
        "SYSTEM\\MountedDevices",

        // Volume-Informationen
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt",

        // Windows Portable Devices
        "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",

        // Device Classes
        "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
        "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{10497b1b-ba51-44e5-8318-a65c837b6661}",

        // User-spezifische Einträge
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
    };

    bool isElevated() {
        BOOL isElevated = FALSE;
        PSID adminGroup = NULL;

        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isElevated);
            FreeSid(adminGroup);
        }
        return isElevated == TRUE;
    }

    bool deleteRegistryKey(HKEY hRootKey, const std::string& subKey) {
        LONG result = RegDeleteTreeA(hRootKey, subKey.c_str());
        return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
    }

    bool cleanUSBStorageKeys(HKEY hRootKey, const std::string& basePath) {
        HKEY hKey;
        LONG result = RegOpenKeyExA(hRootKey, basePath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey);

        if (result != ERROR_SUCCESS) {
            return true; // Schlüssel existiert nicht
        }

        std::vector<std::string> subKeys;
        DWORD index = 0;
        char subKeyName[256];
        DWORD subKeyNameSize;

        // Alle Unterschlüssel sammeln
        while (true) {
            subKeyNameSize = sizeof(subKeyName);
            result = RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameSize,
                NULL, NULL, NULL, NULL);

            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result == ERROR_SUCCESS) {
                subKeys.push_back(std::string(subKeyName));
            }
            index++;
        }

        RegCloseKey(hKey);

        // USB-Storage Schlüssel löschen
        int deletedCount = 0;
        for (const auto& subKey : subKeys) {
            std::string fullPath = basePath + "\\" + subKey;
            if (deleteRegistryKey(hRootKey, fullPath)) {
                deletedCount++;
                std::cout << "  Gelöscht: " << fullPath << std::endl;
            }
        }

        return deletedCount > 0;
    }

    bool cleanMountedDevices() {
        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\MountedDevices",
            0, KEY_READ | KEY_WRITE, &hKey);

        if (result != ERROR_SUCCESS) {
            return true;
        }

        std::vector<std::string> valuesToDelete;
        DWORD index = 0;
        char valueName[256];
        DWORD valueNameSize;
        BYTE valueData[1024];
        DWORD valueDataSize;

        // Alle Werte durchgehen
        while (true) {
            valueNameSize = sizeof(valueName);
            valueDataSize = sizeof(valueData);

            result = RegEnumValueA(hKey, index, valueName, &valueNameSize,
                NULL, NULL, valueData, &valueDataSize);

            if (result == ERROR_NO_MORE_ITEMS) break;

            if (result == ERROR_SUCCESS) {
                std::string name(valueName);
                // USB-bezogene Mounted Devices identifizieren
                if (name.find("\\??\\USBSTOR#") != std::string::npos ||
                    name.find("\\??\\Volume{") != std::string::npos) {
                    valuesToDelete.push_back(name);
                }
            }
            index++;
        }

        // USB-bezogene Mounted Device Einträge löschen
        int deletedCount = 0;
        for (const auto& valueName : valuesToDelete) {
            if (RegDeleteValueA(hKey, valueName.c_str()) == ERROR_SUCCESS) {
                deletedCount++;
                std::cout << "  Mounted Device gelöscht: " << valueName << std::endl;
            }
        }

        RegCloseKey(hKey);
        return deletedCount > 0;
    }

    bool cleanUserMountPoints() {
        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2",
            0, KEY_READ | KEY_WRITE, &hKey);

        if (result != ERROR_SUCCESS) {
            return true;
        }

        std::vector<std::string> subKeys;
        DWORD index = 0;
        char subKeyName[256];
        DWORD subKeyNameSize;

        // Alle Mount Points sammeln
        while (true) {
            subKeyNameSize = sizeof(subKeyName);
            result = RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameSize,
                NULL, NULL, NULL, NULL);

            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result == ERROR_SUCCESS) {
                subKeys.push_back(std::string(subKeyName));
            }
            index++;
        }

        RegCloseKey(hKey);

        // Mount Points löschen
        int deletedCount = 0;
        for (const auto& subKey : subKeys) {
            std::string fullPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\" + subKey;
            if (deleteRegistryKey(HKEY_CURRENT_USER, fullPath)) {
                deletedCount++;
                std::cout << "  Mount Point gelöscht: " << subKey << std::endl;
            }
        }

        return deletedCount > 0;
    }

public:
    void showWarning() {
        std::cout << "======================================================================\n";
        std::cout << "USB Registry Cleaner v1.0, Simon Giesen, TQS, Sensitec Mainz 160626\n";
        std::cout << "======================================================================\n\n";
        std::cout << "WARNUNG: Dieses Programm löscht USB-Geräteinformationen aus der Registry!\n";
        std::cout << "- Es wird empfohlen, vorher ein Registry-Backup zu erstellen\n";
        std::cout << "- Alle angeschlossenen USB-Geräte sollten getrennt werden\n";
        std::cout << "- Administrator-Rechte sind erforderlich\n\n";

        if (!isElevated()) {
            std::cout << "FEHLER: Dieses Programm muss als Administrator ausgeführt werden!\n";
            std::cout << "Bitte starten Sie die Kommandozeile als Administrator neu.\n";
            return;
        }

        std::cout << "Möchten Sie fortfahren? (j/n): ";
        char choice;
        std::cin >> choice;

        if (choice != 'j' && choice != 'J') {
            std::cout << "Vorgang abgebrochen.\n";
            return;
        }

        performCleanup();
    }

    void performCleanup() {
        std::cout << "\nBereinigung wird gestartet...\n\n";

        int totalCleaned = 0;

        // USB und USBSTOR Einträge bereinigen
        std::cout << "1. Bereinige USB-Geräteinformationen...\n";
        if (cleanUSBStorageKeys(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USB")) {
            totalCleaned++;
        }
        if (cleanUSBStorageKeys(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR")) {
            totalCleaned++;
        }

        // Mounted Devices bereinigen
        std::cout << "\n2. Bereinige Mounted Devices...\n";
        if (cleanMountedDevices()) {
            totalCleaned++;
        }

        // User Mount Points bereinigen
        std::cout << "\n3. Bereinige Benutzer Mount Points...\n";
        if (cleanUserMountPoints()) {
            totalCleaned++;
        }

        // Weitere Registry-Bereiche
        std::cout << "\n4. Bereinige weitere USB-Registry-Einträge...\n";
        std::vector<std::string> additionalPaths = {
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt",
            "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"
        };

        for (const auto& path : additionalPaths) {
            if (deleteRegistryKey(HKEY_LOCAL_MACHINE, path)) {
                std::cout << "  Gelöscht: " << path << std::endl;
                totalCleaned++;
            }
        }

        std::cout << "\n========================================\n";
        std::cout << "Bereinigung abgeschlossen!\n";
        std::cout << "Bereiche bereinigt: " << totalCleaned << std::endl;
        std::cout << "========================================\n\n";
        std::cout << "Empfehlung: Starten Sie den Computer neu, damit alle Änderungen wirksam werden.\n";
    }
};

int main() {
    SetConsoleOutputCP(CP_UTF8); // UTF-8 für deutsche Umlaute

    USBRegistryCleaner cleaner;
    cleaner.showWarning();

    std::cout << "\nDrücken Sie eine beliebige Taste zum Beenden...";
    std::cin.get();
    std::cin.get();

    return 0;
}
