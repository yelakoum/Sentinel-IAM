#!/bin/bash

# 1. On crée le dossier de destination
mkdir -p classes

# 2. La Compilation
# On dit à Java de chercher les .jar dans Server/Log/ (avec l'étoile * pour tous les prendre)
javac -d classes -cp "Server/Log/*" $(find Server -name "*.java")

# 3. L'Exécution
# Le classpath DOIT contenir le dossier 'classes' (où est ton Main) ET tes .jar
java -cp "classes:Server/Log/*" Server.Main