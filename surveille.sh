#tail -f cette commande permet de lire les nouvele lignea jouter
#grep pour recuperer tou les truc critique 
#nc netcat avec entca en va pouvoir envoyer des text brut au serveur
tail -f /var/log/auth.log | grep "Failed" | nc localhost 8080



