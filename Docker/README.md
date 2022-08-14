# Iniciar los contenedores
> docker-compose up -d
> sh start.sh (entra en el contenedor attacker)

# Para mirar las ips de los contenedores dentro de su red
> docker network ls
> docker network inspect inquisitor_default

# Contraseña del servidor ftp:
- User: ftp
- Password: ftp

# Para ver el tráfico usar 'tcpdump'
> tcpdump -n (escucha sin resolver las ips)
> tcpdump -D (lista de interfaces)
> tcpdump -ni eth0 arp (solo muestra los paquetes arp)
# Para ver tabla arp usar comando 'arp' del paquete net-tools
> arp -n (ver tabla arp sin resolver ips)
Para aumentar la tabla hacer 'ping'
# Para mandar paquetes arp usar comando 'arping' del paquete arping
Esto no aumenta la tabla arp
