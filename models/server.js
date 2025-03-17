const express = require('express');
const https = require('https');
const fs = require('fs');
const ejs = require('ejs');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const { createLogger, transports, format } = require("winston");

class Server {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 5000;  
        this.conectMongo();  
        this.middlewares();
        this.routes();
        this.listen();

        this.logger = createLogger({
            format: format.combine(
                format.timestamp(),
                format.json()
            ),
            transports: [
                new transports.File({ filename: 'registro.log' }) // Log de eventos
            ]
        });
    }

    conectMongo() {
        mongoose.connect('mongodb://localhost:27017/Usuarios2025', { 
            useNewUrlParser: true, 
            useUnifiedTopology: true 
        })
        .then(() => {
            console.log("Conectado a MongoDB");
            this.logger.info({ message: "Conectado a MongoDB" });
        })
        .catch(err => {
            console.error("Error al conectar a MongoDB:", err);
            this.logger.error({ message: "Error al conectar a MongoDB", error: err.toString() });
        });

        let Schema = mongoose.Schema;
        const userSchema = new Schema({
            user: String,
            pass: String,
            rol: String
        });

        this.userModel = mongoose.model('usuario', userSchema); 
    }

    middlewares() {
        this.app.use(express.static('./public'));
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));

        this.app.set('view engine', 'ejs');
        this.app.set('trust proxy', 1);

        this.app.use(session({
            secret: 'clave',
            resave: false,
            saveUninitialized: true,
            cookie: { secure: false }
        }));
    }

    routes() {
        this.app.use((req, res, next) => {
            this.logger.info({ message: `Solicitud recibida: ${req.method} ${req.url}` });
            next();
        });

        this.app.post('/registrar', async (req, res) => {
            let usuario = req.body.usuario;
            let cont = req.body.cont;
        
            console.log("Datos recibidos:", usuario, cont); 
        
            if (!usuario || !cont) {
                return res.status(400).send("Faltan datos en el formulario.");
            }
        
            let salt = bcrypt.genSaltSync(12);
            let hashCont = bcrypt.hashSync(cont, salt);
        
            let nuevoUsuario = new this.userModel({
                user: usuario,
                pass: hashCont,
                rol: 'visitante'
            });
        
            try {
                await nuevoUsuario.save();
                res.redirect('/login.html');  
            } catch (error) {
                console.error('Error al registrar usuario:', error);
                this.logger.error({ message: "Error al registrar usuario", error: error.toString() });
                res.status(500).send('Error al registrar usuario.');
            }
        });       

        this.app.get('/index', (req, res) => {
            if (req.session.user) {
                res.render('index', { nombre: req.session.user });
            } else {
                this.logger.warn({ message: "Acceso denegado - usuario no autenticado" });
                res.status(401).render('error', { mensaje: 'Acceso denegado. Inicia sesión.' });
            }
        });

        this.app.post('/login', async (req, res) => {
            let User = req.body.username;
            let Password = req.body.password;
        
            let consulta = await this.userModel.findOne({ user: User });

            if (consulta) {  
                const match = bcrypt.compareSync(Password, consulta.pass);
                if (match) {
                    req.session.user = User;  
                    req.session.rol = consulta.rol;
            
                    this.logger.info({
                        message: `Usuario logueado: ${User}`,
                        name: 'login',
                        stack: 'ruta login'
                    });
            
                    res.render('index', { nombre: User });                  
                } else {
                    this.logger.warn({
                        message: `Intento de login fallido: ${User} (Contraseña incorrecta)`
                    });
                    res.status(401).render('error', { mensaje: 'Contraseña incorrecta.' });
                }
            } else {
                this.logger.warn({ message: `Intento de login con usuario no registrado: ${User}` });
                res.status(404).render('error', { mensaje: 'Usuario no encontrado.' });
            }
        });
    }

    listen() {
        https.createServer({
            cert: fs.readFileSync('cert.crt'),
            key: fs.readFileSync('private.key')
        }, this.app).listen(this.port, () => {
            console.log('Servidor corriendo en https://127.0.0.1:' + this.port);
            this.logger.info({ message: `Servidor iniciado en puerto ${this.port}` });
        });
    }
}

module.exports = Server;
