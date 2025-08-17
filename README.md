# ssl-test

Programa para rápidamente poder: 

- ver qué certificados presenta un sitio (y sus datos mas importantes)
- descargar esos certificados para poder incluir alguno de ellos a nuestro almacén de confianza
- chequear si podemos establecer conexion SSL a ese sitio, ya sea con las CAs del sistema operativo, o con un almacén de confianza a medida 


Soporta el uso de proxy.

## Uso

ssl-test  [--custom-ts \<tls-bundle.pem\>] [--proxy \<server:port\>] \<url-sitio\>

Ejemplos:

ssl-test  login.mypurecoud.com  
ssl-test  aso-dev-ar.work-02.platform.bbva.com   
ssl-test  --custom-ts mi-bundle-tls.pem  cards.prisma.com  
ssl-test  --proxy  proxycfg:1082  cards.prisma.com  