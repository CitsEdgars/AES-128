#include "AES_GUI.h"
#include "imgui.h"
#include <vector>
#include <string>
#include <Windows.h>

#include "AES.h"
#include "MAC.h"

#include <iostream>
#include <fstream>

#pragma warning(disable:4996)

using namespace std;

struct Funcs
{
    static int MyResizeCallback(ImGuiInputTextCallbackData* data)
    {
        if (data->EventFlag == ImGuiInputTextFlags_CallbackResize)
        {
            ImVector<char>* my_str = (ImVector<char>*)data->UserData;
            IM_ASSERT(my_str->begin() == data->Buf);
            my_str->resize(data->BufSize); // NB: On resizing calls, generally data->BufSize == data->BufTextLen + 1
            data->Buf = my_str->begin();
        }
        return 0;
    }

    static bool MyInputTextMultiline(const char* label, ImVector<char>* my_str, const ImVec2& size = ImVec2(0, 0), ImGuiInputTextFlags flags = 0)
    {
        IM_ASSERT((flags & ImGuiInputTextFlags_CallbackResize) == 0);
        return ImGui::InputTextMultiline(label, my_str->begin(), (size_t)my_str->size(), size, flags | ImGuiInputTextFlags_CallbackResize, Funcs::MyResizeCallback, (void*)my_str);
    }
};

namespace AES_GUI
{
    static char inputText[1024 * 16] = "";
    static char AES_key[49] = "";
    static char CMAC_key[49] = "";
    static char CMAC_hash[49] = "";

    static int currCMAC[16];
    static int generatedKey[16];

    static char inputKeyPhrase[128] = "";
    static char keyField[128] = "";
    static char output[1024 * 16] = "";
    static char cmac[128 * 16] = "";

    static string inputFileName = "";
    static string AESKeyName = "";
    static string MACKeyName = "";
    static string MACHashName = "";

    static bool inputTextFileFound = false;
    static bool AESKeyFileFound = false;
    static bool MACKeyFileFound = false;
    static bool MACHashFileFound = false;

    static bool readFromOutput = false;
    static bool generatedCMAC = false;
    static bool matchedCMAC = false;

    static bool generatedAESKey = false;
    static bool generatedCMACKey = false;


    static int pixelCharRatio = 7;
    static int panel_size = 340;

    vector <string> filenames;
    static int selected = 0;

    static int letters_counted = 0;

    unsigned int parse_char_to_int(char c) {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return 10 + c - 'a';
        if ('A' <= c && c <= 'F') return 10 + c - 'A';
    }

    char* parse_int_to_hex_chars(int i) {
        char hexVal[2] = {};
        int num_val1 = i / 0x10;
        int num_val2 = i % 0x10;

        if (num_val1 <= 9) hexVal[0] = (char)0x30 + num_val1;
        else hexVal[0] = (char)0x57 + num_val1;

        if (num_val2 <= 9) hexVal[1] = (char)0x30 + num_val2;
        else hexVal[1] = (char)0x57 + num_val2;

        return hexVal;
    }

    vector <char> getFileContents(string fileName) {
        ifstream input;

        unsigned char byte = 0;
        vector <char> fileContents;
        input.open(fileName);
        while (input.is_open()) {
            while (input >> std::noskipws >> byte) {
                fileContents.push_back(byte);
            }
            break;
        }
        return fileContents;
    }

    bool generateKey(char seedPhrase[]) {
        FILE* file = fopen("temp.txt", "w");
        fputs(inputKeyPhrase, file);
        fclose(file);
        MAC hash(1);

        //Randomizable if necessary for random keys
        //in case a 1 time password is required
        int session_key[16] = { 0x2b, 0x7e, 0x15, 0x16,
                                0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88,
                                0x09, 0xcf, 0x4f, 0x3c };

        hash.generateCMAC(session_key, "temp.txt");
        for (int z = 0; z < 16; z++) generatedKey[z] = hash.CMAC[z];

        bool status = false; //0 for successfule, otherwise failed
        status = remove("temp.txt");
        return !status;
    }

    vector<string> get_all_files_names_within_folder(std::string folder)
    {
        vector<string> names;
        string search_path = folder + "/*.txt";
        WIN32_FIND_DATA fd;
        HANDLE hFind = ::FindFirstFile(search_path.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                // read all (real) files in current folder
                // , delete '!' read other 2 default folder . and ..
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    names.push_back(fd.cFileName);
                }
            } while (::FindNextFile(hFind, &fd));
            ::FindClose(hFind);
        }
        return names;
    }

    void RenderUI() {

        static bool opt_fullscreen = true;
        static bool opt_padding = false;
        static ImGuiDockNodeFlags dockspace_flags = ImGuiDockNodeFlags_None;

        ImGuiWindowFlags window_flags = ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoDocking;
        if (opt_fullscreen)
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(viewport->WorkPos);
            ImGui::SetNextWindowSize(viewport->WorkSize);
            ImGui::SetNextWindowViewport(viewport->ID);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            window_flags |= ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
            window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;
        }
        else
        {
            dockspace_flags &= ~ImGuiDockNodeFlags_PassthruCentralNode;
        }

        if (dockspace_flags & ImGuiDockNodeFlags_PassthruCentralNode)
            window_flags |= ImGuiWindowFlags_NoBackground;

        if (!opt_padding)
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
        ImGui::Begin("DockSpace Demo", nullptr, window_flags);
        if (!opt_padding)
            ImGui::PopStyleVar();

        if (opt_fullscreen)
            ImGui::PopStyleVar(2);

        ImGuiIO& io = ImGui::GetIO();
        if (io.ConfigFlags & ImGuiConfigFlags_DockingEnable)
        {
            ImGuiID dockspace_id = ImGui::GetID("MyDockSpace");
            ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dockspace_flags);
        }

        if (ImGui::BeginMenuBar())
        {
            if (ImGui::BeginMenu("Options"))
            {
                // Disabling fullscreen would allow the window to be moved to the front of other windows,
                // which we can't undo at the moment without finer window depth/z control.
                ImGui::MenuItem("Fullscreen", NULL, &opt_fullscreen);
                ImGui::MenuItem("Padding", NULL, &opt_padding);
                ImGui::Separator();

                if (ImGui::MenuItem("Flag: NoSplit", "", (dockspace_flags & ImGuiDockNodeFlags_NoSplit) != 0)) { dockspace_flags ^= ImGuiDockNodeFlags_NoSplit; }
                if (ImGui::MenuItem("Flag: NoResize", "", (dockspace_flags & ImGuiDockNodeFlags_NoResize) != 0)) { dockspace_flags ^= ImGuiDockNodeFlags_NoResize; }
                if (ImGui::MenuItem("Flag: NoDockingInCentralNode", "", (dockspace_flags & ImGuiDockNodeFlags_NoDockingInCentralNode) != 0)) { dockspace_flags ^= ImGuiDockNodeFlags_NoDockingInCentralNode; }
                if (ImGui::MenuItem("Flag: AutoHideTabBar", "", (dockspace_flags & ImGuiDockNodeFlags_AutoHideTabBar) != 0)) { dockspace_flags ^= ImGuiDockNodeFlags_AutoHideTabBar; }
                if (ImGui::MenuItem("Flag: PassthruCentralNode", "", (dockspace_flags & ImGuiDockNodeFlags_PassthruCentralNode) != 0, opt_fullscreen)) { dockspace_flags ^= ImGuiDockNodeFlags_PassthruCentralNode; }
                ImGui::Separator();
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        // ENCRYPTION / DECRYPTION PANEL
        ImGui::Begin("AES");

        static ImGuiComboFlags flags = 0;
        ImGui::PushItemWidth(120);
        const char* algorithms[] = { "AES-128" };
        static int algo_current_idx = 0;
        const char* algo_preview_value = algorithms[algo_current_idx];
        if (ImGui::BeginCombo("Algorithm", algo_preview_value, flags))
        {
            for (int n = 0; n < IM_ARRAYSIZE(algorithms); n++)
            {
                const bool is_selected = (algo_current_idx == n);
                if (ImGui::Selectable(algorithms[n], is_selected))
                    algo_current_idx = n;

                // Set the initial focus when opening the combo (scrolling + keyboard navigation focus)
                if (is_selected)
                    ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        ImGui::PushItemWidth(120);
        const char* items[] = { "CBC", "OFB" };
        static int item_current_idx = 0; 
        const char* combo_preview_value = items[item_current_idx];
        if (ImGui::BeginCombo("Chaining", combo_preview_value, flags))
        {
            for (int n = 0; n < IM_ARRAYSIZE(items); n++)
            {
                const bool is_selected = (item_current_idx == n);
                if (ImGui::Selectable(items[n], is_selected))
                    item_current_idx = n;
                if (is_selected)
                    ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        static bool inputTextFromFile = false;
        ImGui::Text("Input text:");
        ImGui::SameLine();
        ImGui::Checkbox("From file", &inputTextFromFile);

        if (!inputTextFromFile) {
            ImGui::BeginDisabled();
            if (inputTextFileFound) memset(inputText, 0, sizeof(inputText));
            inputTextFileFound = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Select File")) {
            ImGui::OpenPopup("input_select");
        }

        if (ImGui::BeginPopupModal("input_select")) {
            if (ImGui::Button("Up one level", ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 2))) {
                ImGui::CloseCurrentPopup();
            }
            filenames = get_all_files_names_within_folder(".");
            int counter = 0;
            for (string fileName : filenames) {
                if (ImGui::Selectable(fileName.c_str(), selected == counter)) {
                    selected = counter;
                    inputTextFileFound = true;
                }
                counter++;
            }
            inputFileName = filenames[selected];
            ImGui::EndPopup();
        }
        if (!inputTextFromFile) ImGui::EndDisabled();

        if (inputTextFromFile) ImGui::BeginDisabled();
                
        if (inputTextFromFile && inputTextFileFound) {
            int counter = 0;
            int nl_counter = 0;
            vector <char> outputFile = getFileContents(inputFileName.c_str());
            for (char sym : outputFile) {
                //Small quick-hack for text wrapping (from file)
                if (sym == '\n'){
                    nl_counter = 0;
                }
                //Number of chars that can be filled in 340 pixels = 48
                if ((nl_counter % 48) + 1 == 48) {
                    inputText[counter] = '\n';
                    counter++;
                    nl_counter = 0;
                }
                nl_counter++;
                //End of hack
                inputText[counter] = sym;
                counter++;
            }
        }
        ImGui::InputTextMultiline("##InputText", inputText, IM_ARRAYSIZE(inputText),
            ImVec2(panel_size, ImGui::GetTextLineHeight() * 10));

        if (inputTextFromFile) ImGui::EndDisabled();

        //AES KEY
        static bool fromFileAESKey = false;
        ImGui::Text("AES key:");
        ImGui::SameLine();
        ImGui::Checkbox("From file ", &fromFileAESKey);

        if (!fromFileAESKey) {
            ImGui::BeginDisabled();
            if (AESKeyFileFound) memset(AES_key, 0, sizeof(AES_key));
            AESKeyFileFound = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Select AES key")) {
            ImGui::OpenPopup("AES_key_select");
        }

        if (ImGui::BeginPopupModal("AES_key_select")) {
            if (ImGui::Button("Up one level", ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 2))) {
                ImGui::CloseCurrentPopup();
            }
            filenames = get_all_files_names_within_folder(".");
            int counter = 0;
            for (string fileName : filenames) {
                if (ImGui::Selectable(fileName.c_str(), selected == counter)) {
                    selected = counter;
                    AESKeyFileFound = true;
                }
                counter++;
            }
            AESKeyName = filenames[selected];
            ImGui::EndPopup();
        }
        if (!fromFileAESKey) {
            ImGui::EndDisabled();

        }
        if (fromFileAESKey) ImGui::BeginDisabled();
        if (fromFileAESKey && AESKeyFileFound) {
            int counter = 0;
            vector <char> outputFile = getFileContents(AESKeyName);
            for (char sym : outputFile) {
                AES_key[counter] = sym;
                counter++;
            }
        }
        ImGui::InputTextMultiline("##AES KEY", AES_key, IM_ARRAYSIZE(AES_key), ImVec2(panel_size, ImGui::GetTextLineHeight() * 5));
        if (fromFileAESKey) ImGui::EndDisabled();

        //CMAC HASH
        static bool fromFileMAC = false;
        ImGui::Text("MAC hash:");
        ImGui::SameLine();
        ImGui::Checkbox("From file   ", &fromFileMAC);

        if (!fromFileMAC) {
            ImGui::BeginDisabled();
            if (MACHashFileFound) memset(CMAC_hash, 0, sizeof(CMAC_hash));
            MACHashFileFound = false;
        }

        ImGui::SameLine();
        if (ImGui::Button("Select MAC hash")) {
            ImGui::OpenPopup("MAC_hash_select");
        }

        if (ImGui::BeginPopupModal("MAC_hash_select")) {
            if (ImGui::Button("Up one level", ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 2))) {
                ImGui::CloseCurrentPopup();
            }
            filenames = get_all_files_names_within_folder(".");
            int counter = 0;
            for (string fileName : filenames) {
                if (ImGui::Selectable(fileName.c_str(), selected == counter)) {
                    selected = counter;
                    MACHashFileFound = true;
                }
                counter++;
            }
            MACHashName = filenames[selected];
            ImGui::EndPopup();
        }
        if (!fromFileMAC) {
            ImGui::EndDisabled();
            
        }
        if (fromFileMAC) ImGui::BeginDisabled();
        
        if (fromFileMAC && MACHashFileFound) {
            int counter = 0;
            int nl_counter = 0;
            vector <char> outputFile = getFileContents(MACHashName);
            for (char sym : outputFile) {
                CMAC_hash[counter] = sym;
                counter++;
            }
        }
        ImGui::InputTextMultiline("##MAC HASH", CMAC_hash, IM_ARRAYSIZE(CMAC_hash), ImVec2(panel_size, ImGui::GetTextLineHeight() * 5));
        if (fromFileMAC) ImGui::EndDisabled();

        //MAC KEY
        static bool fromFileMACKey = false;
        ImGui::Text("MAC key:");
        ImGui::SameLine();
        ImGui::Checkbox("From file  ", &fromFileMACKey);

        if (!fromFileMACKey) {
            ImGui::BeginDisabled();
            if (MACKeyFileFound) memset(CMAC_key, 0, sizeof(CMAC_key));
            MACKeyFileFound = false;
        }

        ImGui::SameLine();
        if (ImGui::Button("Select MAC key")) {
            ImGui::OpenPopup("MAC_key_select");
        }

        if (ImGui::BeginPopupModal("MAC_key_select")) {
            if (ImGui::Button("Up one level", ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 2))) {
                ImGui::CloseCurrentPopup();
            }
            filenames = get_all_files_names_within_folder(".");
            int counter = 0;
            for (string fileName : filenames) {
                if (ImGui::Selectable(fileName.c_str(), selected == counter)) {
                    selected = counter;
                    MACKeyFileFound = true;
                }
                counter++;
            }
            MACKeyName = filenames[selected];
            ImGui::EndPopup();
        }
        if (!fromFileMACKey) {
            ImGui::EndDisabled();

        }
        if (fromFileMACKey) ImGui::BeginDisabled();
        if (fromFileMACKey && MACKeyFileFound) {
            int counter = 0;
            vector <char> outputFile = getFileContents(MACKeyName);
            for (char sym : outputFile) {
                CMAC_key[counter] = sym;
                counter++;
            }
        }
        ImGui::InputTextMultiline("##MAC KEY", CMAC_key, IM_ARRAYSIZE(CMAC_key), ImVec2(panel_size, ImGui::GetTextLineHeight() * 5));
        if (fromFileMACKey) ImGui::EndDisabled();

        ImGui::Text(" "); // Placeholder

        if (ImGui::Button("Encrypt", ImVec2(panel_size, ImGui::GetTextLineHeight() * 3))) {
            static int key[16];
            static int keyCounter = 0;
            int hexVal = 0;
            for (char sym : AES_key) {
                if (sym == ' ') {
                    key[keyCounter] = hexVal;
                    hexVal = 0;
                    keyCounter++;
                } else {
                    hexVal = hexVal * 0x10 + parse_char_to_int(sym);
                }
            }
            string tempFile = "input_temp.txt";
            if (!inputTextFromFile) {
                FILE* file = fopen(tempFile.c_str(), "w");
                fputs(inputText, file);
                fclose(file);
            }
            AES enc(key, 10);

            switch (item_current_idx) {
                case 0: //CBC
                    if (!inputTextFromFile) {
                        enc.encryptTextCBC(tempFile, "output.txt");
                        remove(tempFile.c_str());
                    }
                    else enc.encryptTextCBC(inputFileName.c_str(), "output.txt");
                    readFromOutput = true;
                    break;
                case 1: //OFB
                    if (!inputTextFromFile) {
                        enc.encryptTextOFB(tempFile, "ouptut.txt");
                        remove(tempFile.c_str());
                    } else enc.encryptTextOFB(inputFileName.c_str(), "output.txt");
                    readFromOutput = true;
                    break;
                default:
                    break;
            }
            remove("input_temp.txt");
        }; // RUN ENCRYPTION

        if (ImGui::Button("Decrypt", ImVec2(panel_size, ImGui::GetTextLineHeight() * 3))) {
            static int key[16];
            static int keyCounter = 0;
            int hexVal = 0;
            for (char sym : AES_key) {
                if (sym == ' ') {
                    key[keyCounter] = hexVal;
                    hexVal = 0;
                    keyCounter++;
                }
                else {
                    hexVal = hexVal * 0x10 + parse_char_to_int(sym);
                }
            }
            string tempFile = "input_temp.txt";
            if (!inputTextFromFile) {
                FILE* file = fopen(tempFile.c_str(), "w");
                fputs(inputText, file);
                fclose(file);
            }
            AES enc(key, 10);
            switch (item_current_idx) {
            case 0: //CBC
                if (!inputTextFromFile) {
                    enc.decryptTextCBC(tempFile, "output.txt");
                    remove(tempFile.c_str());
                }
                else enc.decryptTextCBC(inputFileName.c_str(), "output.txt");
                readFromOutput = true;
                break;
            case 1: //OFB
                if (!inputTextFromFile) {
                    enc.decryptTextOFB(tempFile, "output.txt");
                    remove(tempFile.c_str());
                }
                else enc.decryptTextOFB(inputFileName.c_str(), "output.txt");
                readFromOutput = true;
                break;
            default:
                break;
            }
        }; // RUN DECRYPTION

        if (item_current_idx != 1) ImGui::BeginDisabled(); //CMAC is only calculated for OFB

        if (ImGui::Button("Generate CMAC", ImVec2(panel_size, ImGui::GetTextLineHeight() * 3))) {
            static int key[16];
            static int keyCounter = 0;
            unsigned int hexVal = 0;
            for (int i = 0; i < 48; i++) {
                if (CMAC_key[i] == ' ') {
                    key[keyCounter] = hexVal;
                    hexVal = 0;
                    keyCounter++;
                }
                else {
                    hexVal = hexVal * 0x10 + parse_char_to_int(CMAC_key[i]);
                }
            }
            //if (keyCounter == 15) key[keyCounter] = hexVal; //Dont know
            // this was a temp fix for incorrect file format

            MAC hash(1);

            if (!inputTextFromFile) hash.generateCMAC(key, "input_temp.txt");
            else hash.generateCMAC(key, inputFileName.c_str());

            std::ofstream outputStream;
            outputStream.open("output_CMAC.txt");

            if (outputStream.is_open()) {
                for (int i = 0; i < 16; i++) {
                    currCMAC[i] = hash.CMAC[i];
                    outputStream << std::hex << hash.CMAC[i] << " ";
                }
                outputStream.close();
            }
            generatedCMAC = true;
        }; // GENERATE MAC


        if (ImGui::Button("Verify CMAC", ImVec2(panel_size, ImGui::GetTextLineHeight() * 3))) {
            static int key[16];
            static int keyCounter = 0;
            unsigned int hexVal = 0;
            for (int i = 0; i < 48; i++) {
                if (CMAC_key[i] == ' ') {
                    key[keyCounter] = hexVal;
                    hexVal = 0;
                    keyCounter++;
                }
                else {
                    hexVal = hexVal * 0x10 + parse_char_to_int(CMAC_key[i]);
                }
            }
            MAC hash(1);
            if (!inputTextFromFile) matchedCMAC = hash.verifyCMAC(currCMAC, "output.txt", key);
            else matchedCMAC = hash.verifyCMAC(currCMAC, "output.txt", key);
        }; // VERIFY CMAC

        if (item_current_idx != 1) ImGui::EndDisabled();


        // KEY GENERATING PANEL
        ImGui::Begin("Key generation");
        
        ImGui::InputTextWithHint(" ", "Enter passphrase here (up to 128 characters)", inputKeyPhrase, IM_ARRAYSIZE(inputKeyPhrase));
        static bool savedKey = false;

        ImGui::SameLine();
        if (ImGui::Button("Generate AES key")) {
            if (generateKey(inputKeyPhrase)) {
                for (int i = 0; i < 16; i++) {
                    keyField[i * 3] = parse_int_to_hex_chars(generatedKey[i])[0];
                    keyField[i * 3 + 1] = parse_int_to_hex_chars(generatedKey[i])[1];
                    keyField[i * 3 + 2] = ' ';
                }
            }
            generatedAESKey = true;
            generatedCMACKey = false;
            savedKey = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Generate CMAC key")) {
            if (generateKey(inputKeyPhrase)) {
                for (int i = 0; i < 16; i++) {
                    keyField[i * 3] = parse_int_to_hex_chars(generatedKey[i])[0];
                    keyField[i * 3 + 1] = parse_int_to_hex_chars(generatedKey[i])[1];
                    keyField[i * 3 + 2] = ' ';
                }
            }
            generatedAESKey = false;
            generatedCMACKey = true;
            savedKey = false;
        }

        ImGui::Text("Generated key:");
        ImGui::SameLine();

        static ImGuiInputTextFlags keyFlags = ImGuiInputTextFlags_ReadOnly;
        ImGui::InputText("##KeyField", keyField, IM_ARRAYSIZE(keyField), keyFlags);
        ImGui::SameLine();

        if (generatedAESKey || generatedCMACKey) {
            if (ImGui::Button("Save key")) {
                std::ofstream output;
                if (generatedAESKey) output.open("AES_key_generated.txt");
                if (generatedCMACKey) output.open("CMAC_key_generated.txt");
                for (int i = 0; i < 16; i++) {
                    output << std::hex << generatedKey[i] << " ";
                }
                output.close();
                savedKey = true;
            }
        }

        if (generatedCMACKey && savedKey) ImGui::Text("Key saved to \"CMAC_key_generated.txt\"");
        if (generatedAESKey && savedKey) ImGui::Text("Key saved to \"AES_key_generated.txt\"");
        // OUTPUT PANEL
        ImGui::Begin("Program output");

        ImGui::Text("Generated output:");
        
        if (readFromOutput) {
            memset(output, 0, sizeof(output));
            int counter = 0;
            vector <char> outputFile = getFileContents("output.txt");
            for (char sym : outputFile) {
                output[counter] = sym;
                counter++;
            }
        }
        ImGui::InputTextMultiline("Output", output, IM_ARRAYSIZE(output),
                        ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16),
                        ImGuiInputTextFlags_ReadOnly);

        if (readFromOutput) ImGui::Text("Output saved to \"output.txt\"");

        ImGui::Text("  "); //Placeholder
        ImGui::Text("Generated CMAC:"); 
        if (generatedCMAC) {
            memset(cmac, 0, sizeof(cmac));
            int counter = 0;
            vector <char> outputFile = getFileContents("output_CMAC.txt");
            for (char sym : outputFile) {
                cmac[counter] = sym;
                counter++;
            }
        }
        ImGui::InputTextMultiline("CMAC", cmac, IM_ARRAYSIZE(cmac),
            ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 4),
            ImGuiInputTextFlags_ReadOnly);

        if (generatedCMAC) ImGui::Text("CMAC saved to \"output_CMAC.txt\"");//Must be saved to some file

        if (matchedCMAC) ImGui::Text("CMAC has been verified and matches!");//Must be saved to some file
        else ImGui::Text("CMAC has been not been verified or doesn't match!");//Must be saved to some file

        ImGui::End();
        ImGui::End();
        ImGui::End();
        ImGui::End();

        

        //ImGui::ShowDemoWindow();

    }
}
