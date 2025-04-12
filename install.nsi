# Название и версия инсталлятора
Outfile "PWManager_Installer.exe"
InstallDir $LOCALAPPDATA\PWManager

# Папка для временных файлов
InstallDirRegKey HKCU "Software\PWManager" "Install_Dir"

# Разрешаем создание ярлыков
RequestExecutionLevel user

# Раздел для файлов
Section "Install PWManager"

    # Устанавливаем PWManager.exe в папку пользователя
    SetOutPath $INSTDIR
    File "PWManager.exe"

    # Устанавливаем icon.ico
    File "icon.ico"

    # Создаем ярлык на рабочем столе
    CreateShortCut "$DESKTOP\PWManager.lnk" "$INSTDIR\PWManager.exe" "" "$INSTDIR\icon.ico"

SectionEnd

# Раздел для деинсталляции
Section "Uninstall"

    # Удаляем установленную программу
    Delete "$INSTDIR\PWManager.exe"
    Delete "$INSTDIR\icon.ico"
    
    # Удаляем ярлык с рабочего стола
    Delete "$DESKTOP\PWManager.lnk"

    # Удаляем папку с программой (если она пуста)
    RMDir $INSTDIR

SectionEnd
