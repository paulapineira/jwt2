
# Autenticación y Autorización de usuarios con JWT

##Pasos para ejecutar el desafio de Soft Jobs

Instalar las Dependencias: Ejecuta npm install para crear la carpeta node_modules y demás dependencias

Configurar las siguientes variables con tus datos (esto se debe hacer en el .env de momento el archivo tiene las credenciales de mi servidor pero se pueden modificar según se necesite)

user=your_postgres_user
host=localhost
database=your_database_name
password=your_postgres_password
port=5432

Para realizar este desafío necesitarás ejecutar el siguiente script sql en tu terminal psql para
crear la base de datos y la tabla que utilizaremos:

CREATE DATABASE softjobs;
\c softjobs;
CREATE TABLE usuarios ( id SERIAL, email VARCHAR(50) NOT NULL, password
VARCHAR(60) NOT NULL, rol VARCHAR(25), lenguage VARCHAR(20) );
SELECT * FROM usuarios;


Iniciar el Proyecto: Ejecuta npm start o node server.js para correr el servidor.# jwt2
# jwt2
