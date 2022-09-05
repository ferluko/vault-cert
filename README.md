# Cómo proteger las aplicaciones nativas de la nube con HashiCorp Vault y Cert Manager

Cuando hablamos de seguridad en las organizaciones, generalmente nos referimos a la prevención de la pérdida de datos, o también a la automatización e integración segura de aplicaciones. Para lograr esto, es necesario saber quién está haciendo qué con qué activos, y ahí es donde entra en juego la gestión de identidades, como HashiCorp Vault. El "quién" en la ecuación se vuelve muy importante. 

Los certificados emitidos correctamente permiten la seguridad de extremo a extremo a través de una cadena de identidades confiable (PKI). Resulta que la emisión de certificado pasa ser una tarea cotidina y repetitida dado que debe acompañar la cedencia del despliegue de aplicacion, es decir, esta gestion debe ser tan ágil como el propio proceso de despligue, por lo tanto se requiere automatización más allá de la gestión de identidades.

Como ocurre con la mayoría de los objetivos de seguridad, suele haber tensión entre el requisito de hacer que las cosas sean seguras y tratar de hacer el trabajo real. El arte aquí es equilibrar los dos requisitos en conflicto, una forma de reducir la carga del desarrollador e infraestructura es automatizar tanto como sea posible.

En este articulo, se probará cómo se puede usar OpenShift junto con Cert Manager y HashiCorp Vault para lograr un proceso automatizado y reproducible para aumentar la seguridad de las aplicaciones.

Desde el punto de vista de infraestructura y seguridad informatica, este enfoque automatizado es fácil de usar y también está instrumentado para que sepamos qué está pasando y podamos tomar las medidas adecuadas si falla. 
#

## Autoridad Certificante o Certificate Authority (CA)

El propósito de una autoridad de certificación (CA) es validar y emitir certificados. Una CA puede ser una entidad u organización de terceros que ejecuta su propio proveedor para emitir certificados digitales.

Una CA intermedia es una CA firmada por una CA superior (por ejemplo, una root CA u otra CA intermedia) y firma otras CA (por ejemplo, otra CA intermedia o subordinada).

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
Generar el certificado:

```sh

openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -extensions v3_ca -config openssl.cnf
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----

Country Name [CH]:

State or Province Name [ZH]:

Locality Name [Zurich]:

Organization Name [Red Hat]:

Company Name [company.io]:

```

Como se muestra en el resultado anterior, el valor definido en el archivo de configuración openssl.cnf incluye una entrada req_distinguished_name que se utiliza como conjunto de valores predeterminado al generar el certificado. Se pueden utilizar los valores predeterminados o se puede proporcionar un conjunto de valores definido por el usuario.    

Ahora con la root CA, podemos comenzar con el segundo paso de la cadena: la CA intermedia a nivel del cluster.

Generamos la clave privada de CA intermedia:

```sh
cd  ../intermediate 

openssl  genrsa  -out  ca.key  2048
```

Generamos el CSR correspondiente.

```sh
openssl req -new -sha256 -key ca.key -out ca.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.

-----
Country Name (2 letter code) []:CH
State or Province Name (full name) []:ZH
Locality Name (eg, city) []:Zurich
Organization Name (eg, company) []:Red Hat
Organizational Unit Name (eg, section) []:RH
Common Name (eg, fully qualified host name) []:int.company.io
Email Address []:
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
```

Asegúrese de que el Country Name y el Common Name estén definidos, ya que la política ( policy_strict ) establecida en openssl.cnf requiere un Country Name y Common Name coincidente.

Creamos el certificado intermedio.

```sh

openssl ca -config ../root/openssl.cnf -extensions v3_intermediate_ca -days 365 -notext -md sha256 -in ca.csr -out ca.crt

...

Certificate is to be certified until May 12 12:52:52 2023 GMT (365 days)

Sign the certificate? [y/n]:y
1 out of 1 certificate requests certified, commit? [y/n]y

Write out database with 1 new entries
Data Base Updated
```

Nuestra CA intermedia a nivel del cluster ya está lista para ser utilizada.
#
## Issuer con Cert Manager
Lo primero que deberá configurar después de haber instalado cert-manager es que se cree un issuer que luego se puede usar para emitir certificados.

Los issuers son recursos de Kubernetes que representan a las autoridades de certificación (CA) que pueden generar certificados firmados al cumplir con las solicitudes de firma de certificados.

El tipo de issuer más simple es la CA, que hace referencia al secreto TLS de Kubernetes que contiene un certificate-key pair.

Genere certificados SSL para Vault usando Cert Manager.
Antes de poder instalar Vault, los certificados deben aprovisionarse dentro de un namespaces creado desde cero.

Primero, defina namespace donde queremos instalar Vault:

```sh
oc new-project hashicorp
```

Desde el directorio intermediate, creemos el secreto de Kubernetes que contiene el certificado generado anteriormente

```sh
oc create secret tls intermediate --cert=${CERT_ROOT}/intermediate/ca.crt --key=${CERT_ROOT}/intermediate/ca.key -n hashicorp
```

Una vez que se crea el secreto, podemos aplicar un issuer CR de Cert Manager de tipo CA al clúster:

```sh
cat <<EOF | oc apply -f -
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: int-ca-issuer
spec:
  ca:
    secretName: intermediate
EOF
```

Verifiquemos el estado del issuer para confirmar que se creó correctamente:

```sh
oc  obtener  emisor  int-ca-emisor 

NOMBRE           LISTO      EDAD 

int-ca-emisor  Verdadero       5s
```

> NOTA: Este issuer de Cert Manager específico, contiene la autoridad de certificación intermedia que se usa estrictamente para firmar el certificado de Vault únicamente. Ninguna otra aplicación solicitará certificados.

Ahora crearemos un Certificado CR para HashiCorp Vault, pero, primero debemos definir algunas variables que utlizaremos durante todo el proceso:

```sh
export BASE_DOMAIN=$(oc get dns cluster -o jsonpath='{.spec.baseDomain}')
export VAULT_HELM_RELEASE=vault
export VAULT_ROUTE=${VAULT_HELM_RELEASE}.apps.$BASE_DOMAIN
export VAULT_ADDR=https://${VAULT_ROUTE}
export VAULT_SERVICE=${VAULT_HELM_RELEASE}-active.hashicorp.svc
```

Implementamos el certificado:

```sh
cat <<EOF|oc apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: vault-certs
spec:
  secretName: vault-certs
  issuerRef:
    name: int-ca-issuer
    kind: Issuer
  dnsNames: 
  - ${VAULT_ROUTE}
  # Service Active FQDN
  - ${VAULT_SERVICE}
  organization:
  - company.io
EOF
```





[//]: # (links references)

[Cert Manager]: <https://cert--manager-io.translate.goog/?_x_tr_sl=auto&_x_tr_tl=es&_x_tr_hl=es&_x_tr_pto=wapp>