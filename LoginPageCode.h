if (showLoginScreen) {
    ImGui::SetNextWindowSize(ImVec2(340, 400), ImGuiCond_Once);
    if (ImGui::Begin("LUNAR CLIENT LOGIN", 0, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar)) {
        
        ImGui::Spacing();
        ImGui::Text(OBFUSCATE(ICON_FA_STAR " VIP LUNAR  " ICON_FA_CHECK_CIRCLE));
        ImGui::Spacing();

        ImGui::Text(ICON_FA_PASTE " LOGIN TO CONTINUE");
        ImGui::Spacing();
        
        static char licenseKey[128] = "";
        static std::string loginMessage = "";
        
        ImGui::PushItemWidth(-1);
        ImGui::InputText("##key", licenseKey, sizeof licenseKey);
        ImGui::PopItemWidth();
        
        if (ImGui::Button(ICON_FA_PASTE " PASTE KEY", ImVec2(ImGui::GetContentRegionAvailWidth(), 55))) {
            std::string clipboard = getClipboard();
            strncpy(licenseKey, clipboard.c_str(), sizeof(licenseKey) - 1);
            licenseKey[sizeof(licenseKey) - 1] = '\0';
        }
        
        if (ImGui::Button(ICON_FA_KEY " LOGIN TO CONTINUE " ICON_FA_CHECK_CIRCLE, ImVec2(ImGui::GetContentRegionAvailWidth(), 55))) {
            if (strlen(licenseKey) > 0) {
                loginMessage = "Verifying license...";
                ImGui::Render();
                
                loginMessage = Login(licenseKey);
                
                if (bValid) {
                    showLoginScreen = false;
                    ImGuiOK = true;
                }
            } else {
                loginMessage = "Please enter a license key";
            }
        }
        
        if (!loginMessage.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 1.0f), "%s", loginMessage.c_str());
        }
        
        ImGui::End();
    }
