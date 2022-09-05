# Cómo proteger las aplicaciones nativas de la nube con HashiCorp Vault y Cert Manager

Cuando hablamos de seguridad en las organizaciones, generalmente nos referimos a la prevención de la pérdida de datos, o también a la automatización e integración segura de aplicaciones. Para lograr esto, es necesario saber quién está haciendo qué con qué activos, y ahí es donde entra en juego la gestión de identidades, como HashiCorp Vault. El "quién" en la ecuación se vuelve muy importante. 

Los certificados emitidos correctamente permiten la seguridad de extremo a extremo a través de una cadena de identidades confiable (PKI). Resulta que la emisión de certificado pasa ser una tarea cotidina y repetitida dado que debe acompañar la cedencia del despliegue de aplicacion, es decir, esta gestion debe ser tan ágil como el propio proceso de despligue, por lo tanto se requiere automatización más allá de la gestión de identidades.

Como ocurre con la mayoría de los objetivos de seguridad, suele haber tensión entre el requisito de hacer que las cosas sean seguras y tratar de hacer el trabajo real. El arte aquí es equilibrar los dos requisitos en conflicto, una forma de reducir la carga del desarrollador e infraestructura es automatizar tanto como sea posible.

En este articulo, se probará cómo se puede usar OpenShift junto con Cert Manager y HashiCorp Vault para lograr un proceso automatizado y reproducible para aumentar la seguridad de las aplicaciones.

Desde el punto de vista de infraestructura y seguridad informatica, este enfoque automatizado es fácil de usar y también está instrumentado para que sepamos qué está pasando y podamos tomar las medidas adecuadas si falla. 
#

## Autoridad Certificante o Certificate Authority (CA)

El propósito de una autoridad de certificación (CA) es validar y emitir certificados. Una CA puede ser una entidad u organización de terceros que ejecuta su propio proveedor para emitir certificados digitales.

Una CA intermedia es una CA firmada por una CA superior (por ejemplo, una CA raíz u otra CA intermedia) y firma otras CA (por ejemplo, otra CA intermedia o subordinada).

Si existe una CA intermedia, se coloca en medio de una cadena de confianza entre el Root CA y el certificado del suscriptor que emite las CA subordinadas. Entonces, ¿no usar una Root CA directamente?

Por lo general, la Root CA  no firma certificados de servidor o cliente directamente. La Root CA se usa solo para crear una o más CA intermedias. El uso de una CA intermedia es principalmente por motivos de seguridad y la Root CA está alojada en otro lugar, en un lugar seguro; fuera de línea y se usa con la menor frecuencia posible.

Por lo tanto, lo mejor es no exponer la Root CA dentro de los entornos de cliente y, en su lugar, emitir una CA intermedia de vida más corta. El uso de CA intermedia también se alinea con las mejores prácticas de la industria.
#

## Jerarquía de CA

En grandes organizaciones, lo ideal seria delegar la emision de certificados a distintas autoridades de certificacion para asi tener un control granular apropiado para cada CA.

Por ejemplo,  la cantidad de certificados puede ser demasiado grande para que una sola CA realice un seguimiento efectivo de los certificados que ha emitido;  o cada departamento dentro de la organizacion  puede tener diferentes políticas y reglas, como períodos de validez; o puede ser importante diferenciar los certificados para la comunicación interna o externa.

El estándar X.509 incluye una plantilla para configurar una jerarquía de CA:
[![N|Solid](https://gitlab.com/semperti-clientes/comafi/poc-vault-certmanager/-/blob/main/images/infografia-jerarquia-ca.png)]
- Root CA aislada en un servidor offline para firmar una CA intermedia primaria.
- CA intermedia a nivel del cluster que permite firmar otra CA intermedia para vault en su rol de issuer
- CA intermedia para Vault en su rol de issuer que emite una ultima CA a nivel granular de cada aplicaion.
- CA intermedia a nivel de aplicacion  que permite la firma de certificados que seran consumidos por las aplicaciones.
- Certificado disponibilizado para las aplicaciones.

#

# Instalación
## Administrador de certificados
El operador [Cert Manager] provisto por JetStack es una herramienta para Kubernetes y Openshift que automatiza la gestión de certificados en entornos nativos de la nube.

Se basa en estas plataformas para proporcionar certificados X.509 y emisores como tipos de recursos de primera clase.
Proporciona herramientas fáciles de usar para administrar certificados, incluidos "certificados como servicio" para habilitar de forma segura a los desarrolladores y aplicaciones que trabajan dentro de un clúster y una API estandarizada para interactuar con múltiples autoridades de certificación (CA). Esto brinda a los equipos de seguridad la confianza para permitir que los desarrolladores administren los certificados en forma de autoservicio.

[Cert Manager] integra una variedad de Emisores, tanto Emisores públicos populares como Emisores privados, y se asegurará de que los certificados sean válidos y estén actualizados, e intentará renovar los certificados en un momento configurado antes de su vencimiento.

#

## Crear la cadena de CA
Comencemos desde cero y simulemos la creación de nuestra propia autoridad de certificación y la construcción de la jerarquía de CA.

Vamos a crear el root CA certificate-key pair utilizando el programa OpenSSL.

[![N|Solid](https://gitlab.com/semperti-clientes/comafi/poc-vault-certmanager/-/blob/main/images/root-ca.png)]

Primero, nos dirigimos a un directorio para el cual se crearán los certificados.
Alli definiremos esa ruta como una variable de entorno que reutilizaremos luego.
```sh
export CERT_ROOT=$(pwd)
```
Defina la estructura del directorio:
```sh
mkdir  -p ${CERT_ROOT} /{raíz,intermedio} 
```
Genere la CA certificate-key pair:
```sh
cd ${CERT_ROOT} /root/ openssl genrsa -out ca.key 2048 touch index.txt echo 1000 > serial mkdir -p newcerts 
```

Defina el archivo openssl.cnf:
```sh
cat <<EOF > openssl.cnf
[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ${CERT_ROOT}/root
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/ca.key
certificate       = \$dir/ca.crt

# For certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no

policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName               = match
stateOrProvinceName       = optional
organizationName          = optional
organizationalUnitName    = optional
commonName                = supplied
emailAddress              = optional

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA.
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[req_distinguished_name]
countryName = CH
countryName = Country Name
countryName_default = CH
stateOrProvinceName = State or Province Name
stateOrProvinceName_default = ZH
localityName= Locality Name
localityName_default = Zurich
organizationName= Organization Name
organizationName_default = Red Hat
commonName= Company Name
commonName_default = company.io
commonName_max = 64

[req]
distinguished_name = req_distinguished_name
[ v3_ca ]
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF
```


[//]: # (links references)

[Cert Manager]: <https://cert--manager-io.translate.goog/?_x_tr_sl=auto&_x_tr_tl=es&_x_tr_hl=es&_x_tr_pto=wapp>