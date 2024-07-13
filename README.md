# ssl-test

Programa para rápidamente poder: 

- ver qué certificados presenta un sitio (y sus datos mas importantes)
- descargar esos certificados para poder incluir alguno de ellos a nuestro almacén de confianza
- chequear si podemos establecer conexion SSL a ese sitio, ya sea con las CAs del sistema operativo, o con un almacén de confianza a medida 


## Uso

ssl-test  \<url-sitio\> [truststore.pem]

Ejemplos:

ssl-test  go.dev  
ssl-test  aso-dev-ar.work-02.platform.bbva.com   
ssl-test 