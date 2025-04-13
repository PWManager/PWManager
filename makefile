PYTHON = python
MAIN = main.py

run:
	$(PYTHON) ${MAIN}

build:
	pyinstaller -F -w -i "./icon.ico" ${MAIN}

install:
	pip install -r requirements.txt

clean:
	del PWManager.exe
	del PWManager.zip
	del Output/PWManager-Installer.exe
	rmdir Output

gitadd:
	git add .

gitpush:
	git push

gitpull:
	git pull